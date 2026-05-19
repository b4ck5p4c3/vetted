package vetted

import (
	"context"
	"net"
)

// Tracer is the hook surface the Discoverer calls into so callers
// can wrap discovery in their preferred tracing backend (Sentry,
// OpenTelemetry, ...) without this library taking a dependency on
// any of them.
//
// Lifetime convention: every Start returns a child ctx that's
// passed back to the matching End. Implementations may attach a
// span to that ctx (StartSpan/Finish pattern) or treat the ctx
// as opaque and store state elsewhere.
//
// All methods may be called from multiple goroutines concurrently
// — v4 and v6 cycles run in parallel and each fans out across
// endpoints. Implementations must be safe for concurrent use OR
// document the restriction.
type Tracer interface {
	// CycleStart fires once per Discover call. The returned ctx
	// is the parent for every AttemptStart that follows.
	CycleStart(ctx context.Context) context.Context
	// CycleEnd fires after every Attempt has finished and before
	// Discover returns. Result.V4Err / V6Err carry the final
	// per-family outcome; Result.Attempts has the per-endpoint
	// detail.
	CycleEnd(ctx context.Context, res Result)
	// AttemptStart fires before the HTTP request for one endpoint
	// + family pair. Returned ctx is the parent for the request
	// (and the matching AttemptEnd).
	AttemptStart(ctx context.Context, ep Endpoint, fam Family) context.Context
	// AttemptEnd fires after the HTTP response is parsed (or
	// errored). ip is nil on failure; err is nil on success.
	AttemptEnd(ctx context.Context, ep Endpoint, fam Family, ip net.IP, err error)
}

// NoopTracer satisfies Tracer with no-op implementations. The
// Discoverer uses it when no tracer is provided so the call sites
// don't need nil checks.
type NoopTracer struct{}

func (NoopTracer) CycleStart(ctx context.Context) context.Context { return ctx }
func (NoopTracer) CycleEnd(context.Context, Result)                 {}
func (NoopTracer) AttemptStart(ctx context.Context, _ Endpoint, _ Family) context.Context {
	return ctx
}
func (NoopTracer) AttemptEnd(context.Context, Endpoint, Family, net.IP, error) {}
