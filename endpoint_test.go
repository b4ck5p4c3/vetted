package vetted

// Endpoint + Prober config tests: Validate() and DefaultEndpoints
// invariants.

import (
	"strings"
	"testing"
)

func TestEndpoint_Validate(t *testing.T) {
	good := Endpoint{
		Name:   "ok",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{URL: "https://example.test/", Parser: JSONQuoted()},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good endpoint should validate, got %v", err)
	}

	httpProbe := func() *HTTPProbe { return &HTTPProbe{URL: "u", Parser: JSONQuoted()} }
	cases := []struct {
		name string
		ep   Endpoint
		want string
	}{
		{"missing name", Endpoint{Family: Any, Cost: 1, Prober: httpProbe()}, "Name"},
		{"invalid family", Endpoint{Name: "n", Family: "v7", Cost: 1, Prober: httpProbe()}, "Family"},
		{"non-positive cost", Endpoint{Name: "n", Family: Any, Cost: 0, Prober: httpProbe()}, "Cost"},
		{"missing prober", Endpoint{Name: "n", Family: Any, Cost: 1}, "Prober"},
		{"http missing url", Endpoint{Name: "n", Family: Any, Cost: 1, Prober: &HTTPProbe{Parser: JSONQuoted()}}, "URL"},
		{"http missing parser", Endpoint{Name: "n", Family: Any, Cost: 1, Prober: &HTTPProbe{URL: "u"}}, "Parser"},
		{"http invalid method", Endpoint{Name: "n", Family: Any, Cost: 1, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted(), Method: "BREW"}}, "Method"},
		{"http negative maxbytes", Endpoint{Name: "n", Family: Any, Cost: 1, Prober: &HTTPProbe{URL: "u", Parser: JSONQuoted(), MaxBytes: -1}}, "MaxBytes"},
		{"stun missing addr", Endpoint{Name: "n", Family: Any, Cost: 1, Prober: &STUNProbe{}}, "Addr"},
		{"stun bad addr", Endpoint{Name: "n", Family: Any, Cost: 1, Prober: &STUNProbe{Addr: "no-port"}}, "host:port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.ep.Validate()
			if err == nil {
				t.Fatalf("expected error mentioning %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %q should mention %q", err.Error(), c.want)
			}
		})
	}
}

// TestDefaultEndpoints_AllValidate guarantees that the curated
// DefaultEndpoints list stays well-formed — every entry must pass
// Validate() so New() doesn't panic on first use.
func TestDefaultEndpoints_AllValidate(t *testing.T) {
	for _, ep := range DefaultEndpoints {
		if err := ep.Validate(); err != nil {
			t.Errorf("DefaultEndpoints %q: %v", ep.Name, err)
		}
	}
}

// TestDefaultEndpoints_UniqueNames pins down the operator contract
// that endpoint Name is a unique tag — duplicate names break trace
// tag aggregation and metric labels.
func TestDefaultEndpoints_UniqueNames(t *testing.T) {
	seen := make(map[string]struct{}, len(DefaultEndpoints))
	for _, ep := range DefaultEndpoints {
		if _, dup := seen[ep.Name]; dup {
			t.Errorf("duplicate Name %q in DefaultEndpoints", ep.Name)
		}
		seen[ep.Name] = struct{}{}
	}
}

// TestDefaultEndpoints_HasSTUN guards that the one STUN probe found
// reachable from RU mobile (stun.rtc.yandex.net over TCP) stays in
// the default set — it is the egress-independent backstop.
func TestDefaultEndpoints_HasSTUN(t *testing.T) {
	for _, ep := range DefaultEndpoints {
		if s, ok := ep.Prober.(*STUNProbe); ok {
			if s.Addr != "stun.rtc.yandex.net:3478" {
				t.Errorf("STUN endpoint Addr = %q, want stun.rtc.yandex.net:3478", s.Addr)
			}
			return
		}
	}
	t.Fatal("no STUNProbe in DefaultEndpoints")
}

// TestDefaultEndpoints_VKSTUNPool guards the VK STUN fallback pool:
// six v4 STUN-over-TCP probes on :19302, all in a single Cost tier
// above the primary CostMinimal tier so they fire as a group only
// after the primary probes fail.
func TestDefaultEndpoints_VKSTUNPool(t *testing.T) {
	var n int
	for _, ep := range DefaultEndpoints {
		s, ok := ep.Prober.(*STUNProbe)
		if !ok || !strings.HasPrefix(ep.Name, "vk-stun-") {
			continue
		}
		n++
		if ep.Family != V4 {
			t.Errorf("%s Family = %q, want V4", ep.Name, ep.Family)
		}
		if ep.Cost != 100 {
			t.Errorf("%s Cost = %d, want 100 (fallback tier above CostMinimal)", ep.Name, ep.Cost)
		}
		if !strings.HasSuffix(s.Addr, ":19302") {
			t.Errorf("%s Addr = %q, want :19302", ep.Name, s.Addr)
		}
	}
	if n != 6 {
		t.Errorf("VK STUN pool has %d entries, want 6", n)
	}
}

// TestAttempt_OptionalFromRidesThroughAttempt pins the operator
// contract: when an endpoint sets OptionalFrom, the same string is
// reachable via Attempt.Endpoint.OptionalFrom. Dashboards depend on
// this to filter documented expected-failure noise (lamoda from RU
// mobile, avito from foreign egress) without re-encoding the rules.
func TestAttempt_OptionalFromRidesThroughAttempt(t *testing.T) {
	var found bool
	for _, ep := range DefaultEndpoints {
		if ep.Name == "lamoda-vpn-error" {
			found = true
			if ep.OptionalFrom != "domestic-RU egress" {
				t.Errorf("lamoda-vpn-error OptionalFrom = %q, want %q (mobile-RU deploys depend on this tag)",
					ep.OptionalFrom, "domestic-RU egress")
			}
		}
	}
	if !found {
		t.Fatal("lamoda-vpn-error not in DefaultEndpoints — annotation scaffolding broken")
	}
}

// TestHTTPProbe_MethodDefault pins down the method() helper: empty
// Method → GET, set Method → as-is.
func TestHTTPProbe_MethodDefault(t *testing.T) {
	if got := (&HTTPProbe{}).method(); got != "GET" {
		t.Errorf("empty Method should default to GET, got %q", got)
	}
	if got := (&HTTPProbe{Method: "POST"}).method(); got != "POST" {
		t.Errorf("Method=POST should pass through, got %q", got)
	}
}

// TestHTTPProbe_ReadCap pins down the cap-selection rule. Zero
// MaxBytes → package default. Non-zero → the value verbatim, even
// when smaller than the package default.
func TestHTTPProbe_ReadCap(t *testing.T) {
	if got := (&HTTPProbe{}).readCap(); got != int64(maxResponseBytes) {
		t.Errorf("zero MaxBytes should use package default %d, got %d", maxResponseBytes, got)
	}
	if got := (&HTTPProbe{MaxBytes: 1024}).readCap(); got != 1024 {
		t.Errorf("MaxBytes=1024 should override; got %d", got)
	}
	if got := (&HTTPProbe{MaxBytes: 1024 * 1024}).readCap(); got != 1024*1024 {
		t.Errorf("MaxBytes=1MB should override upwards too; got %d", got)
	}
}

// TestAcceptStatus pins down the per-endpoint status gate. Empty
// list = 200-299 only; explicit list = allowlist of exact codes.
// 2gis and lamoda rely on this to opt 403 past the default 2xx gate.
func TestAcceptStatus(t *testing.T) {
	cases := []struct {
		name   string
		accept []int
		code   int
		want   bool
	}{
		{"default 2xx allows 200", nil, 200, true},
		{"default 2xx allows 299", nil, 299, true},
		{"default 2xx rejects 199", nil, 199, false},
		{"default 2xx rejects 300", nil, 300, false},
		{"default 2xx rejects 403", nil, 403, false},
		{"explicit 200+403 allows 200", []int{200, 403}, 200, true},
		{"explicit 200+403 allows 403", []int{200, 403}, 403, true},
		{"explicit 200+403 rejects 201", []int{200, 403}, 201, false},
		{"explicit 200+403 rejects 500", []int{200, 403}, 500, false},
		{"explicit empty list = default", []int{}, 200, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &HTTPProbe{AcceptStatus: c.accept}
			if got := h.acceptStatus(c.code); got != c.want {
				t.Errorf("acceptStatus(%d) with %v = %v, want %v",
					c.code, c.accept, got, c.want)
			}
		})
	}
}
