//go:build live

// Live smoke tests. Opt-in only - these hit the real RU-allowlist
// endpoints over the network and exist to catch upstream rot
// (antibot reshuffle, parser-key rename, IP filter changes) before
// users hit it. Run with:
//
//	go test -tags=live -timeout=120s ./...
//
// Mobile-RU networks are the target environment for this library,
// so the gate is intentionally generous: as long as at least 5
// endpoints across both families resolve an IP from the current
// egress, the library is "healthy enough" to ship. Per-endpoint
// outcomes get logged as a matrix so a reader can spot the
// regressed entry without re-running anything.

package vetted

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLive_AllDefaultEndpoints(t *testing.T) {
	type outcome struct {
		v4Status string
		v4IP     string
		v4Dur    time.Duration
		v6Status string
		v6IP     string
		v6Dur    time.Duration
	}
	results := make(map[string]*outcome)

	var totalIPs int
	for _, ep := range DefaultEndpoints {
		t.Run(ep.Name, func(t *testing.T) {
			d := New(
				WithEndpoints(ep),
				WithTimeout(15*time.Second),
			)
			res := d.Discover(t.Context())
			o := &outcome{}
			results[ep.Name] = o
			for _, a := range res.Attempts {
				switch a.Family {
				case V4:
					o.v4Dur = a.Duration
					if a.Err == nil {
						o.v4Status = "ok"
						o.v4IP = a.IP.String()
						totalIPs++
					} else {
						o.v4Status = a.FailReason
					}
				case V6:
					o.v6Dur = a.Duration
					if a.Err == nil {
						o.v6Status = "ok"
						o.v6IP = a.IP.String()
						totalIPs++
					} else {
						o.v6Status = a.FailReason
					}
				}
			}
			if o.v4Status == "" {
				o.v4Status = "skip"
			}
			if o.v6Status == "" {
				o.v6Status = "skip"
			}
			if o.v4Status != "ok" && o.v6Status != "ok" {
				t.Logf("no IP from either family: v4=%s v6=%s", o.v4Status, o.v6Status)
			}
		})
	}

	// Emit a matrix so a reader of the log can spot the regressed
	// entry without re-running. Sort by endpoint declaration order
	// (DefaultEndpoints slice) so the output is stable across runs.
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "live endpoint matrix (current egress):")
	fmt.Fprintln(&b, "name                          v4-status      v4-dur    v6-status      v6-dur    filtered-ok  optional-from")
	for _, ep := range DefaultEndpoints {
		o := results[ep.Name]
		if o == nil {
			continue
		}
		filtered := ""
		if ep.FilteredReachable {
			filtered = "yes"
		}
		fmt.Fprintf(&b, "%-30s%-15s%-10s%-15s%-10s%-13s%s\n",
			ep.Name,
			o.v4Status, o.v4Dur.Round(time.Millisecond),
			o.v6Status, o.v6Dur.Round(time.Millisecond),
			filtered, ep.OptionalFrom,
		)
	}
	t.Log(b.String())

	// Healthy-library gate. Five wins across families is generous
	// - even on a heavily filtered network we expect more - but
	// makes the test useful as a regression alarm without forcing
	// a maintainer to chase down every transient flake. Only
	// applies on a full run (every endpoint probed); when the
	// caller narrowed via -run to a single subtest, skip the
	// gate because totalIPs is meaningless on a partial sample.
	const minResolutions = 5
	if len(results) == len(DefaultEndpoints) && totalIPs < minResolutions {
		t.Fatalf("only %d successful IP resolutions across %d endpoints x 2 families; library health below threshold (%d)",
			totalIPs, len(DefaultEndpoints), minResolutions)
	}
}
