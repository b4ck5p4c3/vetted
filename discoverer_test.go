package vetted

// Scaffolding tests. Agent task fills out comprehensive coverage —
// see TESTING_AGENT.md (one-shot brief at repo root).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDiscover_ResolvesIPFromQmsShape — sanity check that the
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
			Name:    "fake",
			URL:     srv.URL,
			Family:  Any,
			Cost:    CostMinimal,
			Headers: map[string]string{"X-Api-Key": "secret"},
			Parser:  JSONKey("ip"),
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
// ones — load-bearing for the metered-network use case.
func TestEligibleTiers_CostOrderAndGrouping(t *testing.T) {
	d := New(WithEndpoints(
		Endpoint{Name: "expensive", URL: "u", Family: Any, Cost: CostHigh, Parser: JSONQuoted()},
		Endpoint{Name: "cheap1", URL: "u", Family: Any, Cost: CostMinimal, Parser: JSONQuoted()},
		Endpoint{Name: "medium", URL: "u", Family: Any, Cost: CostMedium, Parser: JSONQuoted()},
		Endpoint{Name: "cheap2", URL: "u", Family: Any, Cost: CostMinimal, Parser: JSONQuoted()},
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
