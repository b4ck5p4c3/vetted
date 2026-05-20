package vetted

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/enetx/surf"
)

const (
	defaultTimeout  = 5 * time.Second
	defaultInterval = 15 * time.Minute

	// maxResponseBytes caps a single endpoint's response body.
	// CostHigh endpoints (HTML landings) routinely run 30-100 KB
	// but only the first few KB carry the IP — capping at 256 KB
	// is generous enough to survive a service redesign without
	// letting a misconfigured endpoint stream megabytes.
	maxResponseBytes = 256 * 1024
)

// Discoverer is the long-lived state for public-IP discovery.
// Construct with New(opts...). The zero value is NOT useful.
type Discoverer struct {
	endpoints []Endpoint
	maxCost   Cost
	timeout   time.Duration
	tracer    Tracer
	logger    *slog.Logger

	clientV4 *http.Client
	clientV6 *http.Client

	trigger chan struct{}

	latestMu sync.RWMutex
	latest   Result
}

// Option configures a Discoverer at construction time.
type Option func(*Discoverer)

// WithEndpoints replaces the default endpoint set. Each endpoint
// is Validate()d; an invalid entry panics New (programmer error,
// not runtime error — endpoint sets are typically static).
func WithEndpoints(eps ...Endpoint) Option {
	return func(d *Discoverer) { d.endpoints = eps }
}

// WithMaxCost caps endpoint eligibility: only those with Cost <=
// max are considered. Pass 0 to allow every endpoint regardless
// of cost (the default).
func WithMaxCost(max Cost) Option {
	return func(d *Discoverer) { d.maxCost = max }
}

// WithTimeout sets the per-cycle deadline (default 5s). Each
// endpoint attempt within a cycle respects this same budget via
// context propagation; if the deadline elapses, in-flight
// requests cancel and the cycle returns whatever already landed.
func WithTimeout(t time.Duration) Option {
	return func(d *Discoverer) { d.timeout = t }
}

// WithTracer wires a span backend (Sentry, OpenTelemetry, ...).
// Default is NoopTracer; pass your adapter to surface attempts
// in your trace UI.
func WithTracer(t Tracer) Option {
	return func(d *Discoverer) {
		if t != nil {
			d.tracer = t
		}
	}
}

// WithLogger sets the slog Logger for debug-level diagnostic
// output. Nil disables logging (no panics).
func WithLogger(l *slog.Logger) Option {
	return func(d *Discoverer) { d.logger = l }
}

// WithHTTPClient overrides the family-pinned HTTP client. Use
// when the caller needs custom transport hooks (proxy, socket
// protector, ...) that this library can't infer. The provided
// client MUST already be pinned to the named family — passing
// a dual-stack client undermines the V4/V6 split.
func WithHTTPClient(fam Family, c *http.Client) Option {
	return func(d *Discoverer) {
		switch fam {
		case V4:
			d.clientV4 = c
		case V6:
			d.clientV6 = c
		}
	}
}

// New returns a ready-to-use Discoverer.
func New(opts ...Option) *Discoverer {
	d := &Discoverer{
		endpoints: DefaultEndpoints,
		timeout:   defaultTimeout,
		tracer:    NoopTracer{},
		trigger:   make(chan struct{}, 1),
	}
	for _, o := range opts {
		o(d)
	}
	for _, ep := range d.endpoints {
		if err := ep.Validate(); err != nil {
			panic(err)
		}
	}
	if d.clientV4 == nil {
		d.clientV4 = newFamilyClient(V4, d.timeout)
	}
	if d.clientV6 == nil {
		d.clientV6 = newFamilyClient(V6, d.timeout)
	}
	return d
}

// newFamilyClient builds an HTTP client that (a) presents a Chrome
// browser TLS fingerprint + User-Agent via enetx/surf, and (b) is
// pinned to one IP protocol family. Both are load-bearing: the
// HTML-landing-page endpoints (wildberries, tbank, avito) return
// an antibot interstitial without a matching browser JA3/JA4
// fingerprint, and family pinning is what makes the v4/v6 split
// meaningful for dual-stack hostnames like wildberries.ru.
//
// Family pinning mechanism: surf's internal dialer is exposed via
// GetDialer(), and net.Dialer.Control runs per-connection-attempt
// with the resolved IP literal in `address`. We parse the IP,
// reject the wrong family, and let the dialer's built-in fallback
// move on to the next candidate from the resolver result list.
// For a v6-only hostname like ipv6-internet.yandex.net on a v4-only
// host, every Control attempt rejects → dial fails — which is the
// correct outcome for "v6 race on a v4-only network".
//
// Replacing surf's internal dialer entirely would lose its DNS-
// over-TLS / proxy / etc. wiring; mutating just the Control field
// preserves all of that.
func newFamilyClient(family Family, timeout time.Duration) *http.Client {
	c := surf.NewClient().Builder().Impersonate().Chrome().Session().Timeout(timeout).Build().Unwrap()
	dialer := c.GetDialer()
	dialer.Control = familyControl(family)
	std := c.Std()
	std.Timeout = timeout
	return std
}

// familyControl returns a net.Dialer.Control callback that rejects
// connection attempts to addresses of the wrong IP family. Address
// arrives as "host:port" with host always a numeric IP literal at
// this stage (DNS has already resolved). Non-IP host falls through
// to "allow" — we never get here with a literal hostname.
func familyControl(want Family) func(network, address string, c syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil
		}
		is4 := ip.To4() != nil
		switch want {
		case V4:
			if !is4 {
				return fmt.Errorf("family filter: v4 race rejected v6 address %s", host)
			}
		case V6:
			if is4 {
				return fmt.Errorf("family filter: v6 race rejected v4 address %s", host)
			}
		}
		return nil
	}
}

// Result is the outcome of one Discover call.
type Result struct {
	V4       net.IP
	V6       net.IP
	V4Source string // endpoint Name that succeeded for v4; empty on failure
	V6Source string
	V4Err    error
	V6Err    error

	// Attempts records every endpoint hit in this cycle, in
	// completion order. Useful for the Tracer.CycleEnd hook and
	// for ad-hoc post-mortem when discovery flakes.
	Attempts []Attempt

	StartedAt time.Time
	Duration  time.Duration
}

// Attempt is one endpoint × family hit's outcome.
type Attempt struct {
	Endpoint  Endpoint
	Family    Family
	IP        net.IP
	Err       error
	StartedAt time.Time
	Duration  time.Duration
	// HTTPStatus is 0 if the request didn't reach a response.
	HTTPStatus int
	// FailReason classifies Err into a small tag-friendly set;
	// empty on success. See classifyErr.
	FailReason string
}

// Discover runs one v4 + v6 discovery cycle and returns the
// outcome. Latest() reflects the same result after Discover
// returns. Safe for concurrent calls; per-cycle context isolation
// prevents v4 and v6 attempts from sharing cancellation state.
func (d *Discoverer) Discover(ctx context.Context) Result {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	ctx = d.tracer.CycleStart(ctx)

	var wg sync.WaitGroup
	var mu sync.Mutex
	res := Result{StartedAt: started}

	wg.Add(2)
	go func() {
		defer wg.Done()
		ip, src, atts, err := d.runFamily(ctx, V4)
		mu.Lock()
		res.V4, res.V4Source, res.V4Err = ip, src, err
		res.Attempts = append(res.Attempts, atts...)
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		ip, src, atts, err := d.runFamily(ctx, V6)
		mu.Lock()
		res.V6, res.V6Source, res.V6Err = ip, src, err
		res.Attempts = append(res.Attempts, atts...)
		mu.Unlock()
	}()
	wg.Wait()

	res.Duration = time.Since(started)
	d.latestMu.Lock()
	d.latest = res
	d.latestMu.Unlock()
	d.tracer.CycleEnd(ctx, res)
	return res
}

// Latest returns the most recent Result. Zero value if Discover
// has not run yet (V4 / V6 are nil; Attempts is empty). Safe for
// concurrent access.
func (d *Discoverer) Latest() Result {
	d.latestMu.RLock()
	defer d.latestMu.RUnlock()
	return d.latest
}

// Run starts the periodic discovery loop and blocks until ctx is
// cancelled. The loop:
//
//  1. fires one Discover immediately so Latest() is populated
//     before the first interval;
//  2. re-runs every `interval` (default 15min when 0);
//  3. or on Trigger() — the off-cycle refresh.
//
// Set VETTED_DISABLE=1 to suppress the loop entirely (initial
// Discover and ticker both skipped). Useful only for offline test
// environments — callers should not normally need this; constructing
// a Discoverer with a custom (empty) endpoint set is a cleaner way to
// disable discovery at use-site granularity.
func (d *Discoverer) Run(ctx context.Context, interval time.Duration) {
	if os.Getenv("VETTED_DISABLE") == "1" {
		if d.logger != nil {
			d.logger.Debug("vetted: public IP discovery disabled via env")
		}
		return
	}
	if interval <= 0 {
		interval = defaultInterval
	}
	d.Discover(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.Discover(ctx)
		case <-d.trigger:
			d.Discover(ctx)
			ticker.Reset(interval)
		}
	}
}

// Trigger schedules an off-cycle Discover without restarting the
// periodic ticker. Idempotent + non-blocking: multiple Trigger
// calls that arrive while a discovery is in flight coalesce into
// one. Safe for noisy callbacks (mobile NWPathMonitor /
// ConnectivityManager change events).
func (d *Discoverer) Trigger() {
	select {
	case d.trigger <- struct{}{}:
	default:
		// One discovery is already queued; further triggers are
		// noise in this window.
	}
}

// runFamily runs the discovery race for one IP family. Eligible
// endpoints (Family matches or Any, Cost within maxCost) are
// grouped by Cost; tiers are tried in ascending order, all
// endpoints within a tier race in parallel, the first to return
// a parseable family-matching IP wins. Loser attempts within the
// winning tier are recorded in Attempts but the goroutines may
// still be in flight when this returns — context cancel via the
// caller stops them.
func (d *Discoverer) runFamily(parent context.Context, fam Family) (net.IP, string, []Attempt, error) {
	httpClient := d.clientV4
	if fam == V6 {
		httpClient = d.clientV6
	}

	tiers := d.eligibleTiers(fam)
	if len(tiers) == 0 {
		return nil, "", nil, fmt.Errorf("vetted: no endpoints eligible for family %s (maxCost=%d)", fam, d.maxCost)
	}

	var attempts []Attempt
	var lastErr error
	for _, tier := range tiers {
		ip, src, atts, err := d.raceTier(parent, fam, httpClient, tier)
		attempts = append(attempts, atts...)
		if err == nil {
			return ip, src, attempts, nil
		}
		lastErr = err
		if errors.Is(parent.Err(), context.Canceled) || errors.Is(parent.Err(), context.DeadlineExceeded) {
			break
		}
	}
	return nil, "", attempts, lastErr
}

// raceTier fans out parallel HTTP attempts across one cost tier
// and returns the first successful one. The tier shares a child
// context that gets cancelled as soon as a winner lands — losers'
// in-flight HTTP requests then abort with context.Canceled instead
// of running to completion. Every attempt still finishes its span
// (success or canceled) before this returns, so the Tracer sees
// consistent telemetry per cycle.
//
// Mobile RU networks are the primary target: under filtering, the
// cheap API tier routinely contains one fast responder and several
// stalled / 5-second-timeout endpoints. Without the cancel-on-win
// short-circuit, every cycle waited for the slowest tier member
// even though the IP was already in hand — turning a sub-second
// resolution into a multi-second one.
func (d *Discoverer) raceTier(parent context.Context, fam Family, httpClient *http.Client, tier []Endpoint) (net.IP, string, []Attempt, error) {
	type result struct {
		ip  net.IP
		src string
		err error
		att Attempt
	}
	tierCtx, cancel := context.WithCancel(parent)
	defer cancel()
	out := make(chan result, len(tier))
	for _, ep := range tier {
		go func(ep Endpoint) {
			out <- d.attempt(tierCtx, fam, httpClient, ep)
		}(ep)
	}
	var atts []Attempt
	var lastErr error
	var winnerIP net.IP
	var winnerSrc string
	for range tier {
		r := <-out
		atts = append(atts, r.att)
		if r.err == nil && winnerIP == nil {
			winnerIP = r.ip
			winnerSrc = r.src
			cancel()
		}
		if r.err != nil {
			lastErr = r.err
		}
	}
	if winnerIP != nil {
		return winnerIP, winnerSrc, atts, nil
	}
	return nil, "", atts, lastErr
}

// attempt is the per-endpoint goroutine body — HTTP fetch, parse,
// ParseIP, family enforcement, tracer span. The returned struct
// is what raceTier collects to build Attempts.
func (d *Discoverer) attempt(parent context.Context, fam Family, httpClient *http.Client, ep Endpoint) (out struct {
	ip  net.IP
	src string
	err error
	att Attempt
}) {
	started := time.Now()
	out.src = ep.Name
	out.att.Endpoint = ep
	out.att.Family = fam
	out.att.StartedAt = started

	spanCtx := d.tracer.AttemptStart(parent, ep, fam)
	defer func() {
		out.att.Duration = time.Since(started)
		if out.err != nil {
			out.att.Err = out.err
			out.att.FailReason = classifyErr(out.err)
		} else {
			out.att.IP = out.ip
		}
		d.tracer.AttemptEnd(spanCtx, ep, fam, out.ip, out.err)
	}()

	var reqBody io.Reader
	if ep.Body != nil {
		// Fresh reader per attempt — http.Client.Do consumes it.
		reqBody = bytes.NewReader(ep.Body)
	}
	req, err := http.NewRequestWithContext(spanCtx, ep.method(), ep.URL, reqBody)
	if err != nil {
		out.err = err
		return
	}
	for k, v := range ep.Headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		out.err = err
		return
	}
	defer resp.Body.Close()
	out.att.HTTPStatus = resp.StatusCode
	if !ep.acceptStatus(resp.StatusCode) {
		out.err = fmt.Errorf("http %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, ep.readCap()))
	if err != nil {
		out.err = err
		return
	}
	candidate, err := ep.Parser.Parse(resp.Header, body)
	if err != nil {
		out.err = err
		return
	}
	parsed := net.ParseIP(candidate)
	if parsed == nil {
		out.err = fmt.Errorf("not an IP: %q", candidate)
		return
	}
	// Family enforcement. A dual-stack endpoint forced onto tcp4
	// should never return a v6 address — but defence in depth, in
	// case an intermediate proxy / antibot challenge injects a
	// different family into the response body.
	is4 := parsed.To4() != nil
	switch fam {
	case V4:
		if !is4 {
			out.err = fmt.Errorf("expected v4, got v6: %q", candidate)
			return
		}
	case V6:
		if is4 {
			out.err = fmt.Errorf("expected v6, got v4: %q", candidate)
			return
		}
	}
	out.ip = parsed
	return
}

// eligibleTiers buckets the configured endpoints by Cost so the
// caller can iterate cheap-to-expensive. Returns a slice of tiers
// where each inner slice holds endpoints with the same Cost.
// Endpoints whose family doesn't match (and aren't Any) are
// skipped, as are endpoints over maxCost.
func (d *Discoverer) eligibleTiers(fam Family) [][]Endpoint {
	var picked []Endpoint
	for _, ep := range d.endpoints {
		if ep.Family != fam && ep.Family != Any {
			continue
		}
		if d.maxCost > 0 && ep.Cost > d.maxCost {
			continue
		}
		picked = append(picked, ep)
	}
	sort.SliceStable(picked, func(i, j int) bool {
		return picked[i].Cost < picked[j].Cost
	})
	var tiers [][]Endpoint
	var cur []Endpoint
	var curCost Cost
	for _, ep := range picked {
		if len(cur) == 0 || ep.Cost == curCost {
			cur = append(cur, ep)
			curCost = ep.Cost
			continue
		}
		tiers = append(tiers, cur)
		cur = []Endpoint{ep}
		curCost = ep.Cost
	}
	if len(cur) > 0 {
		tiers = append(tiers, cur)
	}
	return tiers
}

// classifyErr buckets a failure reason into a small tag-friendly
// set so trace tags and metrics can count by category instead of
// unique-string counting. The categories are the public contract
// of Attempt.FailReason — renaming a bucket fragments operator
// dashboards that pin on these values.
func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "http "):
		return "non_2xx"
	case strings.HasPrefix(msg, "not an IP"):
		return "parseip_fail"
	case strings.HasPrefix(msg, "expected v"):
		return "family_mismatch"
	case strings.Contains(msg, "not found"),
		strings.Contains(msg, "did not match"):
		return "parser_miss"
	default:
		return "network"
	}
}
