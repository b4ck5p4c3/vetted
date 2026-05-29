package vetted

// Prober tests. The HTTP path is exercised through the Discoverer in
// discoverer_test.go; here we cover STUNProbe directly against a
// hand-rolled STUN-over-TCP server, plus the end-to-end wiring of a
// STUNProbe endpoint through Discover.

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeSTUNServer accepts one TCP STUN Binding Request and replies
// with a response carrying XOR-MAPPED-ADDRESS for wantIP:wantPort.
// Returns the listener address. Closes itself via t.Cleanup.
func fakeSTUNServer(t *testing.T, wantIP net.IP, wantPort uint16) string {
	t.Helper()
	// Listen on the loopback of the family being tested so STUNProbe's
	// tcp4/tcp6 dial (driven by the race family) reaches it.
	listenAddr := "127.0.0.1:0"
	if wantIP.To4() == nil {
		listenAddr = "[::1]:0"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSTUN(conn, wantIP, wantPort)
		}
	}()
	return ln.Addr().String()
}

func serveSTUN(conn net.Conn, ip net.IP, port uint16) {
	defer conn.Close()
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	// Echo back the transaction ID from the request (bytes 8..20).
	txn := hdr[8:20]
	// XOR-MAPPED-ADDRESS attribute value: reserved, family, x-port,
	// x-address. v4 -> 4 address bytes XOR cookie; v6 -> 16 bytes,
	// first 4 XOR cookie, rest XOR transaction ID.
	var attrVal []byte
	if v4 := ip.To4(); v4 != nil {
		attrVal = make([]byte, 8)
		attrVal[1] = 0x01
		binary.BigEndian.PutUint16(attrVal[2:], port^(magicCookie>>16))
		binary.BigEndian.PutUint32(attrVal[4:], binary.BigEndian.Uint32(v4)^magicCookie)
	} else {
		v6 := ip.To16()
		attrVal = make([]byte, 20)
		attrVal[1] = 0x02
		binary.BigEndian.PutUint16(attrVal[2:], port^(magicCookie>>16))
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:], magicCookie)
		copy(mask[4:], txn)
		for i := 0; i < 16; i++ {
			attrVal[4+i] = v6[i] ^ mask[i]
		}
	}

	attr := make([]byte, 0, 4+len(attrVal))
	var at [4]byte
	binary.BigEndian.PutUint16(at[0:], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(at[2:], uint16(len(attrVal)))
	attr = append(attr, at[:]...)
	attr = append(attr, attrVal...)

	resp := make([]byte, 20)
	binary.BigEndian.PutUint16(resp[0:], 0x0101) // Binding Success Response
	binary.BigEndian.PutUint16(resp[2:], uint16(len(attr)))
	binary.BigEndian.PutUint32(resp[4:], magicCookie)
	copy(resp[8:20], txn)
	resp = append(resp, attr...)
	conn.Write(resp)
}

func TestSTUNProbe_ParsesXORMappedAddress(t *testing.T) {
	addr := fakeSTUNServer(t, net.IPv4(203, 0, 113, 9), 51000)
	p := &STUNProbe{Addr: addr}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := p.Probe(ctx, V4, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.IP == nil || res.IP.String() != "203.0.113.9" {
		t.Fatalf("IP = %v, want 203.0.113.9", res.IP)
	}
	if res.HTTPStatus != 0 {
		t.Errorf("HTTPStatus = %d, want 0 for STUN", res.HTTPStatus)
	}
}

// TestSTUNProbe_ParsesV6XORMappedAddress covers the IPv6 path: the
// low 96 bits of XOR-MAPPED-ADDRESS are un-masked with the request
// transaction ID. yandex-stun (Family Any, AAAA present) relies on
// this to answer the v6 race.
func TestSTUNProbe_ParsesV6XORMappedAddress(t *testing.T) {
	want := net.ParseIP("2001:db8::dead:beef")
	addr := fakeSTUNServer(t, want, 50000)
	p := &STUNProbe{Addr: addr}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := p.Probe(ctx, V6, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.IP == nil || !res.IP.Equal(want) {
		t.Fatalf("IP = %v, want %v", res.IP, want)
	}
	if res.IP.To4() != nil {
		t.Errorf("parsed v6 address %v reports as v4", res.IP)
	}
}

// TestSTUNProbe_EndToEndThroughDiscover wires a STUNProbe endpoint
// through a real Discover cycle, confirming the family race, family
// enforcement and Attempt recording all work for the STUN transport.
func TestSTUNProbe_EndToEndThroughDiscover(t *testing.T) {
	addr := fakeSTUNServer(t, net.IPv4(198, 51, 100, 7), 40000)
	d := New(
		WithEndpoints(Endpoint{
			Name: "fake-stun", Family: V4, Cost: CostMinimal,
			Prober: &STUNProbe{Addr: addr},
		}),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "198.51.100.7" {
		t.Fatalf("V4 = %v, want 198.51.100.7 (err: %v)", res.V4, res.V4Err)
	}
	if res.V4Source != "fake-stun" {
		t.Errorf("V4Source = %q, want fake-stun", res.V4Source)
	}
}

// TestSTUNProbe_DialFailureClassifies confirms that an unreachable
// STUN address fails the attempt without crashing - the address is
// valid host:port but nothing listens.
func TestSTUNProbe_DialFailureClassifies(t *testing.T) {
	// Reserved TEST-NET-1 address, port 1 - connection refused / times
	// out quickly, never succeeds.
	p := &STUNProbe{Addr: "192.0.2.1:1"}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := p.Probe(ctx, V4, nil); err == nil {
		t.Fatal("expected dial error to unreachable STUN addr, got nil")
	}
}
