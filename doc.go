// Package vetted resolves a host's public IPv4 and IPv6 by querying
// a curated list of services that stay reachable under RU network
// filtering (the "vetted" allowlist).
//
// # Why this exists
//
// Generic public-IP services (api.ipify.org, ifconfig.co, ipify.org,
// etc.) are useful in unrestricted networks but become unreliable
// the moment a censor or hostile NAT decides to block them. The
// services in this package's default endpoint set are large RU
// commercial sites that the network filter actively WANTS reachable
// (banks, marketplaces, search engines). They are unlikely to be
// blocked in normal operating conditions of the RU segment and
// therefore make better public-IP probes from inside that segment
// than a generic "echo my IP" service.
//
// # What this is not
//
// Not a TURN client, not an IP geolocation library. Single
// responsibility: given a list of endpoints that echo the
// requester's IP, return the IPs visible from the host.
//
// # Transports (Prober)
//
// Each Endpoint carries a Prober that performs the transport-specific
// fetch; the Discoverer owns the family race, cost tiering and
// tracing. Two probers ship: HTTPProbe (fetch a URL, extract the IP
// with a Parser) and STUNProbe (STUN Binding Request over TCP,
// reading XOR-MAPPED-ADDRESS). STUN is TCP-only on purpose - RU
// mobile carriers (measured on Beeline LTE) drop outbound UDP to STUN
// ports while passing TCP, so UDP STUN never answers from the target
// environment. The one reachable RU STUN server, stun.rtc.yandex.net,
// is in the default set and is egress-independent (works in-RU and
// abroad), making it the most reliable backstop. New transports only
// need to implement Prober.
//
// # API shape
//
// Construct a Discoverer with New(opts...). Call Discover(ctx) for
// a one-shot result; Run(ctx, interval) to keep a Latest() snapshot
// updated periodically; Trigger() to force an off-cycle update (the
// typical caller is a mobile network-change hook). All paths
// support a Tracer for span-style observability - Sentry, OpenTelemetry,
// or whatever the caller plugs in. No tracer is required.
//
// # Cost-based selection
//
// Each Endpoint carries a Cost - the approximate response payload
// size in bytes. The Discoverer tries the cheapest eligible
// endpoints first and only falls back to expensive ones (like
// HTML-scraping a 50 KB landing page) when the cheap tier fails.
// Endpoints at the same Cost form one tier and race in parallel;
// as soon as one returns a valid IP the others are cancelled.
// Callers on metered connections cap with WithMaxCost.
//
// # Expected-failure annotation
//
// Some endpoints are documented to fail under a specific egress
// (lamoda probes from domestic-RU IPs always 307-loop; avito /
// wildberries from foreign IPs return antibot stubs with no IP
// echo). Endpoint.OptionalFrom carries that egress label; the
// library does not act on it but it rides through to the Tracer
// via Attempt.Endpoint so operator dashboards can filter the
// documented expected-failure noise from real regressions. Mobile
// RU deployments will see lamoda fail every cycle - that is the
// documented contract, not a bug.
//
// # Family enforcement
//
// V4 and V6 discovery run in parallel with dialer-pinned HTTP
// clients (tcp4 and tcp6 respectively). A response from a v4-pinned
// fetch that somehow parses as a v6 address is rejected - that
// guarantees public_ipv4 never carries a v6 string and vice versa.
package vetted
