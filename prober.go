package vetted

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
)

// ProbeResult is the outcome of one successful Prober.Probe call.
// HTTPStatus is the response code for HTTP transports and 0 for
// transports that have no such concept (STUN). The Discoverer reads
// it for the Attempt record even when Probe returns an error, so a
// non-2xx HTTP failure still surfaces its status in telemetry.
type ProbeResult struct {
	IP         net.IP
	HTTPStatus int
}

// Prober is the transport-specific half of an Endpoint. The
// Discoverer owns the family race, cost tiering, cancellation and
// tracing; a Prober owns one thing — given the race family and the
// family-pinned HTTP client, return the public IP this endpoint
// reports. HTTP probers fetch + parse with the supplied client;
// STUN probers dial their own family-appropriate connection and
// ignore it. New transports (HTTP/3 IP echo, a different STUN
// dialect, ...) only need to implement this interface — the rest
// of the Discoverer doesn't change.
type Prober interface {
	// Probe runs one attempt. fam is always V4 or V6 (never Any) —
	// the Discoverer expands an Any endpoint into one call per
	// family. On the error path Probe should still populate
	// ProbeResult.HTTPStatus when it has one.
	Probe(ctx context.Context, fam Family, httpClient *http.Client) (ProbeResult, error)
	// Validate reports a config error for the owning endpoint name,
	// called from Endpoint.Validate at New() time.
	Validate(epName string) error
}

// HTTPProbe fetches a URL with the family-pinned client and extracts
// the IP from the response with a Parser. This is the transport every
// original vetted endpoint uses.
type HTTPProbe struct {
	URL     string
	Method  string
	Body    []byte
	Headers map[string]string
	Parser  Parser

	// AcceptStatus, when non-empty, lists HTTP status codes treated
	// as "successful enough" to attempt a body parse. Empty (default)
	// means 200-299. Used for services that echo the requester IP in
	// an antibot 403 / VPN-blocker 403.
	AcceptStatus []int

	// MaxBytes overrides the package-default 256 KB response cap for
	// this endpoint. Zero means "use the package default". Used for
	// endpoints whose IP echo sits past 256 KB in a large landing
	// page; set Cost to the same value so tier ordering reflects the
	// bytes actually pulled.
	MaxBytes int
}

func (h *HTTPProbe) method() string {
	if h.Method == "" {
		return "GET"
	}
	return h.Method
}

func (h *HTTPProbe) readCap() int64 {
	if h.MaxBytes > 0 {
		return int64(h.MaxBytes)
	}
	return int64(maxResponseBytes)
}

func (h *HTTPProbe) acceptStatus(code int) bool {
	if len(h.AcceptStatus) == 0 {
		return code >= 200 && code < 300
	}
	for _, c := range h.AcceptStatus {
		if c == code {
			return true
		}
	}
	return false
}

func (h *HTTPProbe) Validate(epName string) error {
	if h.URL == "" {
		return fmt.Errorf("vetted: endpoint %q missing URL", epName)
	}
	if h.Parser == nil {
		return fmt.Errorf("vetted: endpoint %q missing Parser", epName)
	}
	if h.Method != "" {
		if _, ok := knownMethods[h.Method]; !ok {
			return fmt.Errorf("vetted: endpoint %q has invalid Method %q", epName, h.Method)
		}
	}
	if h.MaxBytes < 0 {
		return fmt.Errorf("vetted: endpoint %q has negative MaxBytes %d", epName, h.MaxBytes)
	}
	return nil
}

func (h *HTTPProbe) Probe(ctx context.Context, _ Family, httpClient *http.Client) (ProbeResult, error) {
	var res ProbeResult
	var reqBody io.Reader
	if h.Body != nil {
		// Fresh reader per attempt — http.Client.Do consumes it.
		reqBody = bytes.NewReader(h.Body)
	}
	req, err := http.NewRequestWithContext(ctx, h.method(), h.URL, reqBody)
	if err != nil {
		return res, err
	}
	for k, v := range h.Headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	res.HTTPStatus = resp.StatusCode
	if !h.acceptStatus(resp.StatusCode) {
		return res, fmt.Errorf("http %d", resp.StatusCode)
	}

	// HEAD never carries a body — skip the read so a server that
	// sent Content-Length but no payload (correct for HEAD per
	// RFC 9110, but trips io.ReadAll under surf's HTTP/2 transport
	// with "unexpected EOF") doesn't fail the cycle. Cookie /
	// header-only parsers don't read the body anyway, so passing
	// an empty slice is semantically correct.
	var body []byte
	if h.method() != "HEAD" {
		body, err = io.ReadAll(io.LimitReader(resp.Body, h.readCap()))
		if err != nil {
			return res, err
		}
	}
	candidate, err := h.Parser.Parse(resp.Header, body)
	if err != nil {
		return res, err
	}
	ip := net.ParseIP(candidate)
	if ip == nil {
		return res, fmt.Errorf("not an IP: %q", candidate)
	}
	res.IP = ip
	return res, nil
}

const magicCookie = 0x2112A442

// STUNProbe discovers the public IP by sending a STUN Binding Request
// and reading XOR-MAPPED-ADDRESS from the response. Transport is TCP,
// not UDP: RU mobile carriers (measured on Beeline LTE) drop outbound
// UDP to STUN ports while passing TCP, so UDP STUN never answers from
// the target environment. The only RU STUN server found reachable
// this way is stun.rtc.yandex.net:3478; the field is exported so
// callers can add their own (e.g. a TURN host parsed out of a live
// call config).
type STUNProbe struct {
	Addr string // host:port
}

func (s *STUNProbe) Validate(epName string) error {
	if s.Addr == "" {
		return fmt.Errorf("vetted: endpoint %q missing STUN Addr", epName)
	}
	if _, _, err := net.SplitHostPort(s.Addr); err != nil {
		return fmt.Errorf("vetted: endpoint %q STUN Addr %q not host:port: %w", epName, s.Addr, err)
	}
	return nil
}

func (s *STUNProbe) Probe(ctx context.Context, fam Family, _ *http.Client) (ProbeResult, error) {
	var res ProbeResult
	// Family pinning via the dial network: tcp4 for the v4 race,
	// tcp6 for the v6 race. The reflexive address the server returns
	// is then guaranteed to be of the dialed family, and the
	// Discoverer's post-probe family check is a no-op confirmation.
	network := "tcp4"
	if fam == V6 {
		network = "tcp6"
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, s.Addr)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(req[2:], 0x0000) // length 0
	binary.BigEndian.PutUint32(req[4:], magicCookie)
	if _, err := rand.Read(req[8:20]); err != nil {
		return res, err
	}
	if _, err := conn.Write(req); err != nil {
		return res, err
	}

	hdr := make([]byte, 20)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return res, fmt.Errorf("stun: %w", err)
	}
	msgLen := int(binary.BigEndian.Uint16(hdr[2:]))
	if msgLen < 0 || msgLen > 1024 {
		return res, fmt.Errorf("stun: implausible message length %d", msgLen)
	}
	body := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return res, fmt.Errorf("stun: %w", err)
	}
	ip, err := stunMappedIP(body, req[8:20])
	if err != nil {
		return res, err
	}
	res.IP = ip
	return res, nil
}

// stunMappedIP walks the STUN attributes and returns the address from
// XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS (legacy fallback).
// txn is the 12-byte request transaction ID, needed to un-mask the
// low 96 bits of an IPv6 XOR-MAPPED-ADDRESS.
func stunMappedIP(body, txn []byte) (net.IP, error) {
	for len(body) >= 4 {
		atyp := binary.BigEndian.Uint16(body[0:])
		alen := int(binary.BigEndian.Uint16(body[2:]))
		if 4+alen > len(body) {
			break
		}
		val := body[4 : 4+alen]
		switch atyp {
		case 0x0020: // XOR-MAPPED-ADDRESS
			return parseXORMapped(val, txn)
		case 0x0001: // MAPPED-ADDRESS
			if ip := parseMapped(val); ip != nil {
				return ip, nil
			}
		}
		body = body[4+((alen+3)&^3):]
	}
	return nil, fmt.Errorf("stun: no mapped-address attribute")
}

// parseXORMapped decodes XOR-MAPPED-ADDRESS for IPv4 (family 0x01) and
// IPv6 (0x02). For v4 the 4 address bytes are XORed with the magic
// cookie; for v6 the first 4 are XORed with the cookie and the
// remaining 12 with the request transaction ID (RFC 5389 §15.2).
func parseXORMapped(v, txn []byte) (net.IP, error) {
	switch {
	case len(v) >= 8 && v[1] == 0x01: // IPv4
		ip := make([]byte, 4)
		binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(v[4:])^magicCookie)
		return net.IP(ip), nil
	case len(v) >= 20 && v[1] == 0x02: // IPv6
		if len(txn) < 12 {
			return nil, fmt.Errorf("stun: missing transaction id for v6")
		}
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:], magicCookie)
		copy(mask[4:], txn)
		ip := make([]byte, 16)
		for i := 0; i < 16; i++ {
			ip[i] = v[4+i] ^ mask[i]
		}
		return net.IP(ip), nil
	default:
		return nil, fmt.Errorf("stun: unsupported xor-mapped-address (len %d family %d)", len(v), addrFamily(v))
	}
}

func addrFamily(v []byte) byte {
	if len(v) >= 2 {
		return v[1]
	}
	return 0
}

func parseMapped(v []byte) net.IP {
	switch {
	case len(v) >= 8 && v[1] == 0x01: // IPv4
		return net.IPv4(v[4], v[5], v[6], v[7])
	case len(v) >= 20 && v[1] == 0x02: // IPv6
		ip := make([]byte, 16)
		copy(ip, v[4:20])
		return net.IP(ip)
	default:
		return nil
	}
}
