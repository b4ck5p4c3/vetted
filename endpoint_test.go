package vetted

// Endpoint type tests: Validate() and DefaultEndpoints invariants.

import (
	"strings"
	"testing"
)

func TestEndpoint_Validate(t *testing.T) {
	good := Endpoint{
		Name:   "ok",
		URL:    "https://example.test/",
		Family: Any,
		Cost:   CostMinimal,
		Parser: JSONQuoted(),
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good endpoint should validate, got %v", err)
	}

	cases := []struct {
		name string
		ep   Endpoint
		want string
	}{
		{"missing name", Endpoint{URL: "u", Family: Any, Cost: 1, Parser: JSONQuoted()}, "Name"},
		{"missing url", Endpoint{Name: "n", Family: Any, Cost: 1, Parser: JSONQuoted()}, "URL"},
		{"missing parser", Endpoint{Name: "n", URL: "u", Family: Any, Cost: 1}, "Parser"},
		{"invalid family", Endpoint{Name: "n", URL: "u", Family: "v7", Cost: 1, Parser: JSONQuoted()}, "Family"},
		{"non-positive cost", Endpoint{Name: "n", URL: "u", Family: Any, Cost: 0, Parser: JSONQuoted()}, "Cost"},
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
