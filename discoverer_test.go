package vetted

// Discoverer tests. Hermetic - everything runs against httptest
// servers, no live network. Hand-rolled scaffold tests are kept
// (TestDiscover_ResolvesIPFromQmsShape, TestEligibleTiers_*) and
// extended with race / fallback / Trigger / family-mismatch / error
// classification coverage.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDiscover_ResolvesIPFromQmsShape - sanity check that the
// Discoverer can do one full cycle against a fake endpoint shaped
// like qms.ru. Verifies: header forwarding, JSONKey parser,
// scope-tag-shaped result.
func TestDiscover_ResolvesIPFromQmsShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "secret" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{
			Name:   "fake",
			Family: Any,
			Cost:   CostMinimal,
			Prober: &HTTPProbe{
				URL:     srv.URL,
				Headers: map[string]string{"X-Api-Key": "secret"},
				Parser:  JSONKey("ip"),
			},
		}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(2*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "203.0.113.7" {
		t.Fatalf("V4 = %v, want 203.0.113.7", res.V4)
	}
	if res.V4Source != "fake" {
		t.Errorf("V4Source = %q, want fake", res.V4Source)
	}
}

// TestEligibleTiers_CostOrderAndGrouping pins down the priority
// algorithm: endpoints with equal Cost go into one tier; tiers are
// sorted ascending so cheap tiers fire first. Breaking this would
// silently make expensive endpoints race in parallel with cheap
// ones - load-bearing for the metered-network use case.
func TestEligibleTiers_CostOrderAndGrouping(t *testing.T) {
	d := New(WithEndpoints(
		Endpoint{Name: "expensive", Family: Any, Cost: CostHigh, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
		Endpoint{Name: "cheap1", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
		Endpoint{Name: "medium", Family: Any, Cost: CostMedium, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
		Endpoint{Name: "cheap2", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
	))
	tiers := d.eligibleTiers(V4)
	if len(tiers) != 3 {
		t.Fatalf("got %d tiers, want 3 (Minimal, Medium, High)", len(tiers))
	}
	if len(tiers[0]) != 2 {
		t.Errorf("tier 0 should hold cheap1 + cheap2, got %d entries", len(tiers[0]))
	}
	for i := 1; i < len(tiers); i++ {
		if tiers[i][0].Cost <= tiers[i-1][0].Cost {
			t.Errorf("tier ordering broken at %d: %d <= %d",
				i, tiers[i][0].Cost, tiers[i-1][0].Cost)
		}
	}
}

// TestEligibleTiers_FamilyFilter excludes endpoints whose Family is
// neither Any nor the requested family.
func TestEligibleTiers_FamilyFilter(t *testing.T) {
	d := New(WithEndpoints(
		Endpoint{Name: "v4-only", Family: V4, Cost: CostMinimal, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
		Endpoint{Name: "v6-only", Family: V6, Cost: CostMinimal, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
		Endpoint{Name: "any", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
	))
	v4tiers := d.eligibleTiers(V4)
	if len(v4tiers) != 1 || len(v4tiers[0]) != 2 {
		t.Fatalf("v4 tiers = %#v, want one tier with 2 entries (v4-only + any)", v4tiers)
	}
	v6tiers := d.eligibleTiers(V6)
	if len(v6tiers) != 1 || len(v6tiers[0]) != 2 {
		t.Fatalf("v6 tiers = %#v, want one tier with 2 entries (v6-only + any)", v6tiers)
	}
}

// TestEligibleTiers_MaxCostCap pins the metered-network gate:
// endpoints with Cost > maxCost are dropped before tiering.
func TestEligibleTiers_MaxCostCap(t *testing.T) {
	d := New(
		WithEndpoints(
			Endpoint{Name: "cheap", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
			Endpoint{Name: "expensive", Family: Any, Cost: CostHigh, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted()}},
		),
		WithMaxCost(CostSmall),
	)
	tiers := d.eligibleTiers(V4)
	if len(tiers) != 1 || len(tiers[0]) != 1 || tiers[0][0].Name != "cheap" {
		t.Fatalf("WithMaxCost should drop the expensive endpoint; got %#v", tiers)
	}
}

// TestDiscover_RaceFirstResponderWins fires two endpoints with the
// same Cost; the fast one returns immediately, the slow one would
// take much longer. The cycle returns the fast result and reports
// the fast endpoint as Source.
func TestDiscover_RaceFirstResponderWins(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"203.0.113.1"}`)
	}))
	t.Cleanup(fast.Close)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
			fmt.Fprint(w, `{"ip":"203.0.113.2"}`)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)

	d := New(
		WithEndpoints(
			Endpoint{Name: "slow", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: slow.URL, Parser: JSONKey("ip")}},
			Endpoint{Name: "fast", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: fast.URL, Parser: JSONKey("ip")}},
		),
		WithHTTPClient(V4, fast.Client()),
		WithHTTPClient(V6, fast.Client()),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	// raceTier collects all attempts before returning, but the
	// winner determines V4Source.
	if res.V4Source != "fast" {
		t.Errorf("V4Source = %q, want fast", res.V4Source)
	}
	if res.V4 == nil || res.V4.String() != "203.0.113.1" {
		t.Errorf("V4 = %v, want 203.0.113.1", res.V4)
	}
}

// TestWithFamilies_V4OnlySkipsV6Race verifies that WithFamilies(V4)
// runs only the v4 race: the v6 race never spawns, so an Any endpoint
// is hit once (v4) not twice, and Result.V6 / V6Err / v6 Attempts
// stay zero. This is the "caller knows there's no v6" fast path -
// it avoids the v6-only-host dial timeout that otherwise dominates a
// cycle on a v4-only network.
func TestWithFamilies_V4OnlySkipsV6Race(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `{"ip":"203.0.113.5"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{Name: "any", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: srv.URL, Parser: JSONKey("ip")}}),
		WithFamilies(V4),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "203.0.113.5" {
		t.Fatalf("V4 = %v, want 203.0.113.5", res.V4)
	}
	if res.V6 != nil || res.V6Err != nil {
		t.Errorf("v6 should be untouched: V6=%v V6Err=%v", res.V6, res.V6Err)
	}
	if hits.Load() != 1 {
		t.Errorf("endpoint hit %d times, want 1 (v4 only, no v6 race)", hits.Load())
	}
	for _, a := range res.Attempts {
		if a.Family == V6 {
			t.Errorf("found a V6 attempt (%s) - v6 race should be skipped", a.Endpoint.Name)
		}
	}
}

// TestWithFamilies_EmptyKeepsDefault - passing no valid family (or
// only Any) must not disable discovery; the default both-families
// set is kept.
func TestWithFamilies_EmptyKeepsDefault(t *testing.T) {
	d := New(WithFamilies(Any))
	if len(d.families) != 2 {
		t.Fatalf("families = %v, want default [V4 V6] when no valid family given", d.families)
	}
}

// TestPriorityEndpoints_TriedBeforeDefaults verifies that a
// WithPriorityEndpoints entry wins over a base endpoint even when the
// base endpoint is cheaper and would otherwise be tried first. The
// priority block precedes the whole base block regardless of Cost.
func TestPriorityEndpoints_TriedBeforeDefaults(t *testing.T) {
	var prioHit, baseHit atomic.Int64
	prio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prioHit.Add(1)
		fmt.Fprint(w, `{"ip":"203.0.113.1"}`)
	}))
	t.Cleanup(prio.Close)
	base := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseHit.Add(1)
		fmt.Fprint(w, `{"ip":"203.0.113.2"}`)
	}))
	t.Cleanup(base.Close)

	d := New(
		// Base endpoint is CHEAPER (CostMinimal) than the priority one
		// (CostHigh) - yet priority must still win because the priority
		// block is tried in full before the base block.
		WithEndpoints(Endpoint{Name: "base", Family: V4, Cost: CostMinimal, Prober: &HTTPProbe{URL: base.URL, Parser: JSONKey("ip")}}),
		WithPriorityEndpoints(Endpoint{Name: "prio", Family: V4, Cost: CostHigh, Prober: &HTTPProbe{URL: prio.URL, Parser: JSONKey("ip")}}),
		WithHTTPClient(V4, prio.Client()),
		WithHTTPClient(V6, prio.Client()),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "203.0.113.1" {
		t.Fatalf("V4 = %v, want 203.0.113.1 from priority (err: %v)", res.V4, res.V4Err)
	}
	if res.V4Source != "prio" {
		t.Errorf("V4Source = %q, want prio", res.V4Source)
	}
	if prioHit.Load() == 0 {
		t.Error("priority endpoint never hit")
	}
	if baseHit.Load() != 0 {
		t.Errorf("base endpoint hit %d times - should not run when priority succeeds", baseHit.Load())
	}
}

// TestPriorityEndpoints_FallThroughToDefaults verifies the base set
// still runs when every priority endpoint fails.
func TestPriorityEndpoints_FallThroughToDefaults(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	base := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"203.0.113.42"}`)
	}))
	t.Cleanup(base.Close)

	d := New(
		WithEndpoints(Endpoint{Name: "base", Family: V4, Cost: CostMinimal, Prober: &HTTPProbe{URL: base.URL, Parser: JSONKey("ip")}}),
		WithPriorityEndpoints(Endpoint{Name: "prio-broken", Family: V4, Cost: CostMinimal, Prober: &HTTPProbe{URL: broken.URL, Parser: JSONKey("ip")}}),
		WithHTTPClient(V4, base.Client()),
		WithHTTPClient(V6, base.Client()),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "203.0.113.42" {
		t.Fatalf("V4 = %v, want 203.0.113.42 from base fallback (err: %v)", res.V4, res.V4Err)
	}
	if res.V4Source != "base" {
		t.Errorf("V4Source = %q, want base", res.V4Source)
	}
}

// TestRaceTier_CancelsLosersOnFirstWin pins the mobile-RU perf
// property: as soon as one tier member returns a valid IP, the
// other in-flight requests get context-cancelled and the cycle
// returns instead of waiting for the slowest endpoint. Before
// this short-circuit, every Discover call paid the cost of the
// slowest tier member regardless of when the winner finished.
//
// The test wires a fast endpoint that responds immediately and a
// slow endpoint that would otherwise sleep ~2s, then asserts the
// cycle completes far below the 2s sleep budget AND that the
// slow Attempt is recorded with FailReason="canceled" so tracer
// dashboards still see what happened.
func TestRaceTier_CancelsLosersOnFirstWin(t *testing.T) {
	const slowSleep = 2 * time.Second
	var slowReached atomic.Bool
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"203.0.113.1"}`)
	}))
	t.Cleanup(fast.Close)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowReached.Store(true)
		select {
		case <-time.After(slowSleep):
			fmt.Fprint(w, `{"ip":"203.0.113.2"}`)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)

	// Family: V4 on both so the v6 race exits immediately with
	// "no eligible endpoints" - otherwise the v6 race would still
	// wait for both endpoints to return (family_mismatch never
	// triggers the cancel-on-win path) and mask the v4 short-circuit.
	d := New(
		WithEndpoints(
			Endpoint{Name: "slow", Family: V4, Cost: CostMinimal, Prober: &HTTPProbe{URL: slow.URL, Parser: JSONKey("ip")}},
			Endpoint{Name: "fast", Family: V4, Cost: CostMinimal, Prober: &HTTPProbe{URL: fast.URL, Parser: JSONKey("ip")}},
		),
		WithHTTPClient(V4, fast.Client()),
		WithHTTPClient(V6, fast.Client()),
		WithTimeout(slowSleep+2*time.Second),
	)

	start := time.Now()
	res := d.Discover(t.Context())
	elapsed := time.Since(start)

	if elapsed >= slowSleep {
		t.Fatalf("Discover took %v, expected well under %v (cycle should not wait for slow loser)", elapsed, slowSleep)
	}
	if res.V4 == nil || res.V4.String() != "203.0.113.1" {
		t.Fatalf("V4 = %v, want 203.0.113.1", res.V4)
	}
	if !slowReached.Load() {
		t.Fatal("slow endpoint never received a request - race scaffolding broken")
	}
	var slowAtt *Attempt
	for i := range res.Attempts {
		a := &res.Attempts[i]
		if a.Endpoint.Name == "slow" && a.Family == V4 {
			slowAtt = a
			break
		}
	}
	if slowAtt == nil {
		t.Fatal("no v4 Attempt recorded for slow endpoint - telemetry lost")
	}
	if slowAtt.FailReason != "canceled" {
		t.Errorf("slow Attempt FailReason = %q, want canceled (err=%v)", slowAtt.FailReason, slowAtt.Err)
	}
}

// TestDiscover_FallsThroughCheapTier verifies the discoverer fires
// the next cost tier when every endpoint in the cheap tier fails.
func TestDiscover_FallsThroughCheapTier(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"203.0.113.42"}`)
	}))
	t.Cleanup(working.Close)

	d := New(
		WithEndpoints(
			Endpoint{Name: "cheap-broken", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: broken.URL, Parser: JSONKey("ip")}},
			Endpoint{Name: "expensive-ok", Family: Any, Cost: CostHigh, Prober: &HTTPProbe{URL: working.URL, Parser: JSONKey("ip")}},
		),
		WithHTTPClient(V4, working.Client()),
		WithHTTPClient(V6, working.Client()),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4Source != "expensive-ok" {
		t.Errorf("V4Source = %q, want expensive-ok (fell through cheap tier)", res.V4Source)
	}
	// Both attempts should be recorded - the cheap miss AND the
	// expensive win - for the v4 family.
	var sawBroken, sawOk bool
	for _, a := range res.Attempts {
		if a.Family != V4 {
			continue
		}
		switch a.Endpoint.Name {
		case "cheap-broken":
			sawBroken = true
			if a.FailReason != "non_2xx" {
				t.Errorf("cheap-broken FailReason = %q, want non_2xx", a.FailReason)
			}
		case "expensive-ok":
			sawOk = true
		}
	}
	if !sawBroken || !sawOk {
		t.Errorf("expected both v4 attempts recorded; sawBroken=%v sawOk=%v", sawBroken, sawOk)
	}
}

// TestAttempt_FamilyMismatchRejection - when an endpoint returns
// an IP of the wrong family (e.g. v4 race gets a v6 address back),
// the attempt must error with FailReason = "family_mismatch". Real-
// world cause: an antibot interstitial that hardcodes an example
// address of the wrong family into the response body.
func TestAttempt_FamilyMismatchRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"2001:db8::1"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{
			Name: "v4-returns-v6", Family: V4, Cost: CostMinimal,
			Prober: &HTTPProbe{URL: srv.URL, Parser: JSONKey("ip")},
		}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(2*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 != nil {
		t.Errorf("V4 = %v, want nil (family mismatch rejected)", res.V4)
	}
	var found bool
	for _, a := range res.Attempts {
		if a.Family != V4 {
			continue
		}
		found = true
		if a.FailReason != "family_mismatch" {
			t.Errorf("FailReason = %q, want family_mismatch", a.FailReason)
		}
	}
	if !found {
		t.Fatalf("no v4 attempt recorded")
	}
}

// TestAttempt_ErrorClassification - the four hot-path classifier
// outcomes: timeout/canceled live in classifyErr() direct tests,
// while the remaining buckets ride through a real httptest cycle so
// the wrapping (http.Do wrappers, surf, etc.) doesn't quietly
// reclassify them. FailReason values are operator-dashboard
// contract.
func TestAttempt_ErrorClassification(t *testing.T) {
	type want struct {
		body   string
		status int
		bucket string
		parser Parser
	}
	cases := []want{
		{body: "internal!", status: 500, bucket: "non_2xx", parser: JSONKey("ip")},
		{body: `{"ip":"not-an-ip-at-all"}`, status: 200, bucket: "parseip_fail", parser: JSONKey("ip")},
		{body: `{"address":"203.0.113.7"}`, status: 200, bucket: "parser_miss", parser: JSONKey("ip")},
	}
	for _, c := range cases {
		t.Run(c.bucket, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.status >= 400 {
					http.Error(w, c.body, c.status)
					return
				}
				fmt.Fprint(w, c.body)
			}))
			t.Cleanup(srv.Close)

			d := New(
				WithEndpoints(Endpoint{Name: "t", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: srv.URL, Parser: c.parser}}),
				WithHTTPClient(V4, srv.Client()),
				WithHTTPClient(V6, srv.Client()),
				WithTimeout(2*time.Second),
			)
			res := d.Discover(t.Context())
			var got string
			for _, a := range res.Attempts {
				if a.Family == V4 {
					got = a.FailReason
					break
				}
			}
			if got != c.bucket {
				t.Errorf("FailReason = %q, want %q", got, c.bucket)
			}
		})
	}
}

func TestClassifyErr_Buckets(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
		{errors.New("http 503"), "non_2xx"},
		{errors.New("not an IP: \"foo\""), "parseip_fail"},
		{errors.New("expected v4, got v6: \"::1\""), "family_mismatch"},
		{errors.New("json key \"ip\" not found"), "parser_miss"},
		{errors.New("regex \"...\" did not match"), "parser_miss"},
		{errors.New("dial tcp: connection refused"), "network"},
	}
	for _, c := range cases {
		got := classifyErr(c.err)
		if got != c.want {
			t.Errorf("classifyErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// TestAttempt_HeaderForwarding pins that the Endpoint.Headers map
// reaches the upstream server unmodified. Without this, the qms /
// rt-speedtest endpoints (which require X-Api-Key) would silently
// return 401 and the cycle would fall through to expensive tiers.
func TestAttempt_HeaderForwarding(t *testing.T) {
	var gotKey atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("X-Api-Key"))
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{
			Name: "t", Family: Any, Cost: CostMinimal,
			Prober: &HTTPProbe{
				URL:     srv.URL,
				Headers: map[string]string{"X-Api-Key": "shibboleth"},
				Parser:  JSONKey("ip"),
			},
		}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(2*time.Second),
	)
	d.Discover(t.Context())
	if got, _ := gotKey.Load().(string); got != "shibboleth" {
		t.Errorf("X-Api-Key seen by upstream = %q, want shibboleth", got)
	}
}

// TestTrigger_OffCycleDiscoveryFires - Run is blocked on a long
// interval; Trigger() forces one Discover cycle. Verified by the
// hit counter on the httptest server moving past the initial run.
func TestTrigger_OffCycleDiscoveryFires(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{Name: "t", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: srv.URL, Parser: JSONKey("ip")}}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(2*time.Second),
	)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		// Long interval - only the initial discover + Trigger()s
		// should fire during the test window.
		d.Run(ctx, time.Hour)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Wait for the initial discover (1 hit on v4 + 1 on v6 - same
	// http handler, two independent clients).
	waitForHits(t, &hits, 2, 2*time.Second)

	d.Trigger()
	waitForHits(t, &hits, 4, 2*time.Second)
}

// TestTrigger_MultipleCallsCoalesce - fire Trigger() many times
// while Discover is in flight; only ONE extra cycle should result
// once the in-flight cycle completes. Buffered chan of size 1
// + non-blocking send is the mechanism.
func TestTrigger_MultipleCallsCoalesce(t *testing.T) {
	// gate blocks the http handler until the test releases it.
	gate := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-gate
		hits.Add(1)
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{Name: "t", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: srv.URL, Parser: JSONKey("ip")}}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(5*time.Second),
	)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		d.Run(ctx, time.Hour)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		close(gate) // unblock any straggler handlers so Run returns
		<-done
	})

	// Send many triggers while initial Discover is blocked on
	// `gate`. Without coalescing, all of them would queue.
	for i := 0; i < 50; i++ {
		d.Trigger()
	}
	// Release the initial cycle (2 hits - v4 + v6). The coalesced
	// trigger then fires one more cycle (another 2 hits).
	// Drain four releases of the gate.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 4; i++ {
			gate <- struct{}{}
		}
	}()
	wg.Wait()
	waitForHits(t, &hits, 4, 3*time.Second)

	// Give the loop a small extra window - if Trigger() did NOT
	// coalesce, a 5th hit would queue up. Spin with a deadline
	// rather than time.Sleep to avoid eating clock time on success.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hits.Load() > 4 {
			t.Fatalf("expected coalesced triggers; saw %d hits", hits.Load())
		}
	}
}

// TestRun_EnvDisable - VETTED_DISABLE=1 short-circuits Run so
// neither the initial Discover nor the ticker fires.
func TestRun_EnvDisable(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("VETTED_DISABLE", "1")
	d := New(
		WithEndpoints(Endpoint{Name: "t", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: srv.URL, Parser: JSONKey("ip")}}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(1*time.Second),
	)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx, time.Millisecond)
		close(done)
	}()
	// Run should return immediately. Cancel and wait.
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return promptly with env disable")
	}
	if hits.Load() != 0 {
		t.Errorf("expected 0 hits with env disable, got %d", hits.Load())
	}
}

// TestNoEligibleEndpoints - a Discoverer whose endpoints are all
// for the wrong family (or capped out by maxCost) must surface a
// clear per-family error, not panic.
func TestNoEligibleEndpoints(t *testing.T) {
	d := New(
		WithEndpoints(Endpoint{
			Name: "v6only", Family: V6, Cost: CostMinimal,
			Prober: &HTTPProbe{URL: "https://example.test/", Parser: JSONQuoted()},
		}),
	)
	res := d.Discover(t.Context())
	if res.V4Err == nil || !strings.Contains(res.V4Err.Error(), "no endpoints eligible") {
		t.Errorf("V4Err = %v, want 'no endpoints eligible'", res.V4Err)
	}
}

// TestLatestSnapshot - Latest() returns the most recent Result and
// is safe to call before any Discover (zero value).
func TestLatestSnapshot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)
	d := New(
		WithEndpoints(Endpoint{Name: "t", Family: Any, Cost: CostMinimal, Prober: &HTTPProbe{URL: srv.URL, Parser: JSONKey("ip")}}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(2*time.Second),
	)
	pre := d.Latest()
	if pre.V4 != nil || pre.V6 != nil {
		t.Errorf("Latest before Discover should be zero value")
	}
	d.Discover(t.Context())
	post := d.Latest()
	if post.V4 == nil || post.V4.String() != "203.0.113.7" {
		t.Errorf("Latest after Discover: V4=%v", post.V4)
	}
}

// TestAttempt_MaxBytesAllowsLargeBodies pins the per-endpoint
// MaxBytes override: the server streams 300 KB with the IP at byte
// ~280 KB; the package default cap (256 KB) MUST miss the IP, while
// a MaxBytes of 320 KB MUST capture it. Without this guard the
// ivi-style endpoint (IP past 256 KB) silently regresses to
// parser_miss.
func TestAttempt_MaxBytesAllowsLargeBodies(t *testing.T) {
	const ipNeedle = `"ip":"203.0.113.7"`
	const filler = `"_filler":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"` // 71 bytes
	// Build a 300 KB body with the IP at byte 280 K.
	preamble := []byte(`{"ip":"not-the-real-ip-pad","data":[`)
	body := make([]byte, 0, 300*1024)
	body = append(body, preamble...)
	for len(body) < 280*1024 {
		body = append(body, []byte(filler+",")...)
	}
	// Mark the IP near byte 280 K.
	body = append(body, []byte(`"real":`+ipNeedle+`,`)...)
	for len(body) < 300*1024 {
		body = append(body, []byte(filler+",")...)
	}
	body = append(body, []byte(`{}]}`)...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	// Parser keys off "real":"ip":"..." inside the 280 K marker.
	// We use a Regex parser to specifically match the marker.
	markerParser := Regex(`"real":"ip":"((?:\d{1,3}\.){3}\d{1,3})"`)

	// Default cap (MaxBytes=0): should miss - parser_miss.
	{
		d := New(
			WithEndpoints(Endpoint{
				Name: "default-cap", Family: Any, Cost: CostMinimal,
				Prober: &HTTPProbe{URL: srv.URL, Parser: markerParser},
			}),
			WithHTTPClient(V4, srv.Client()),
			WithHTTPClient(V6, srv.Client()),
			WithTimeout(3*time.Second),
		)
		res := d.Discover(t.Context())
		if res.V4 != nil {
			t.Errorf("default cap should miss IP past 256 KB, got V4=%v", res.V4)
		}
		var saw bool
		for _, a := range res.Attempts {
			if a.Family != V4 {
				continue
			}
			saw = true
			if a.FailReason != "parser_miss" {
				t.Errorf("default cap FailReason = %q, want parser_miss", a.FailReason)
			}
		}
		if !saw {
			t.Fatalf("no v4 attempt recorded for default-cap case")
		}
	}

	// Bumped cap (MaxBytes=320 KB): should hit.
	{
		d := New(
			WithEndpoints(Endpoint{
				Name: "bumped-cap", Family: Any, Cost: CostMinimal,
				Prober: &HTTPProbe{URL: srv.URL, Parser: markerParser, MaxBytes: 320_000},
			}),
			WithHTTPClient(V4, srv.Client()),
			WithHTTPClient(V6, srv.Client()),
			WithTimeout(3*time.Second),
		)
		res := d.Discover(t.Context())
		if res.V4 == nil || res.V4.String() != "203.0.113.7" {
			t.Fatalf("bumped cap should parse IP at byte ~280 K, got V4=%v", res.V4)
		}
	}
}

// TestAttempt_MethodAndBodyForwarded pins down the POST+Body path:
// the upstream MUST see the configured Method + Body verbatim.
// Unlocks JSON-POST APIs (lamoda et al.) that 400 on a plain GET.
func TestAttempt_MethodAndBodyForwarded(t *testing.T) {
	var gotMethod atomic.Value
	var gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod.Store(r.Method)
		raw, _ := io.ReadAll(r.Body)
		gotBody.Store(string(raw))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{
			Name: "post-endpoint", Family: Any, Cost: CostMinimal,
			Prober: &HTTPProbe{
				URL:     srv.URL,
				Method:  "POST",
				Body:    []byte(`{"shape":"empty"}`),
				Headers: map[string]string{"Content-Type": "application/json"},
				Parser:  JSONKey("ip"),
			},
		}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(2*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "203.0.113.7" {
		t.Fatalf("V4 = %v, want 203.0.113.7", res.V4)
	}
	if got, _ := gotMethod.Load().(string); got != "POST" {
		t.Errorf("upstream Method = %q, want POST", got)
	}
	if got, _ := gotBody.Load().(string); got != `{"shape":"empty"}` {
		t.Errorf("upstream Body = %q, want %q", got, `{"shape":"empty"}`)
	}
}

// TestAttempt_DefaultsGETWithNilBody - explicit negative: empty
// Method + nil Body must still produce a GET with no request body,
// matching pre-Method-field behaviour for every existing endpoint.
func TestAttempt_DefaultsGETWithNilBody(t *testing.T) {
	var gotMethod atomic.Value
	var bodyLen atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod.Store(r.Method)
		raw, _ := io.ReadAll(r.Body)
		bodyLen.Store(int64(len(raw)))
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{
			Name: "default", Family: Any, Cost: CostMinimal,
			Prober: &HTTPProbe{URL: srv.URL, Parser: JSONKey("ip")},
		}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(2*time.Second),
	)
	d.Discover(t.Context())
	if got, _ := gotMethod.Load().(string); got != "GET" {
		t.Errorf("default Method = %q, want GET", got)
	}
	if bodyLen.Load() != 0 {
		t.Errorf("default Body length = %d, want 0", bodyLen.Load())
	}
}

// TestAttempt_HEADWithCookieParser pins the litres optimisation:
// when an endpoint's parser only needs headers (Cookie parser),
// HEAD is enough - the upstream must see HEAD, not GET, and the
// parser must extract the IP from the response header even though
// the body is empty. Saves ~256 KB per cycle on the litres path,
// which is the load-bearing win on metered mobile data.
func TestAttempt_HEADWithCookieParser(t *testing.T) {
	var gotMethod atomic.Value
	var bodyBytes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod.Store(r.Method)
		http.SetCookie(w, &http.Cookie{Name: "__ddg8_", Value: "noise", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "__ddg9_", Value: "203.0.113.7", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "__ddg1_", Value: "noise2", Path: "/"})
		if r.Method == "HEAD" {
			return
		}
		n, _ := fmt.Fprint(w, strings.Repeat("X", 256*1024))
		bodyBytes.Store(int64(n))
	}))
	t.Cleanup(srv.Close)

	d := New(
		WithEndpoints(Endpoint{
			Name: "litres-shape", Family: V4, Cost: CostSmall,
			Prober: &HTTPProbe{URL: srv.URL, Method: "HEAD", Parser: Cookie("__ddg9_")},
		}),
		WithHTTPClient(V4, srv.Client()),
		WithHTTPClient(V6, srv.Client()),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "203.0.113.7" {
		t.Fatalf("V4 = %v, want 203.0.113.7 (err: %v)", res.V4, res.V4Err)
	}
	if got, _ := gotMethod.Load().(string); got != "HEAD" {
		t.Errorf("upstream Method = %q, want HEAD", got)
	}
	if bodyBytes.Load() != 0 {
		t.Errorf("upstream wrote %d body bytes - HEAD should never reach the GET branch", bodyBytes.Load())
	}
}

// TestAttempt_FollowsRedirectWithCookieJar simulates the alfabank
// shape: first request answers 307 + Set-Cookie (antibot challenge),
// second request (replayed with cookies) answers 404 + body
// containing the IP. Locks in the structural property the alfabank
// endpoint depends on: the family-pinned HTTP client must follow
// the redirect AND carry forward the cookies so the second hop
// reaches the IP-bearing response.
func TestAttempt_FollowsRedirectWithCookieJar(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if _, err := r.Cookie("spid"); err != nil {
			http.SetCookie(w, &http.Cookie{Name: "spid", Value: "abc", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "spsc", Value: "def", Path: "/"})
			w.Header().Set("Location", r.URL.String())
			w.WriteHeader(http.StatusTemporaryRedirect)
			fmt.Fprint(w, "blank\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"status":"NOT_FOUND","message":"Город не найден, т.к по IP 203.0.113.7 нет информации в системе"}`)
	}))
	t.Cleanup(srv.Close)

	client := srv.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client.Jar = jar

	d := New(
		WithEndpoints(Endpoint{
			Name: "alfa-shape", Family: Any, Cost: CostMinimal,
			Prober: &HTTPProbe{
				URL:          srv.URL,
				AcceptStatus: []int{200, 404},
				Parser:       Regex(`IP\s+((?:\d{1,3}\.){3}\d{1,3})`),
			},
		}),
		WithHTTPClient(V4, client),
		WithHTTPClient(V6, client),
		WithTimeout(3*time.Second),
	)
	res := d.Discover(t.Context())
	if res.V4 == nil || res.V4.String() != "203.0.113.7" {
		t.Fatalf("V4 = %v, want 203.0.113.7 (err: %v)", res.V4, res.V4Err)
	}
	if got := hits.Load(); got < 2 {
		t.Errorf("server hits = %d, want >= 2 (antibot 307 + 404 replay)", got)
	}
}

// waitForHits spins (with short sleeps) until the atomic counter
// reaches `want` or the deadline elapses. Polling is preferable to
// channel signalling here because the upstream server we're
// watching is shared across the discoverer's internal goroutines
// and the test can't wrap that with a channel of its own.
func waitForHits(t *testing.T, c *atomic.Int64, want int64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if c.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("hits = %d, want >= %d within %v", c.Load(), want, within)
}
