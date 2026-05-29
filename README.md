# vetted

`vetted` resolves a host's public IPv4 and IPv6 by querying Russian
commercial services that stay reachable when generic IP-echo services
are blocked.

A network filter can block a generic service like `api.ipify.org` at
will. The default endpoint set in this library targets large RU
commercial sites such as banks, marketplaces, and search engines that
a filter keeps reachable, so they work as public-IP probes from inside
a filtered RU segment where generic providers fail. The library does
one thing. It is not a TURN client and not a geolocation library.

## Install

```
go get github.com/b4ck5p4c3/vetted
```

The module requires Go 1.25 or newer.

## Usage

A one-shot resolution races the v4 and v6 families and returns both
results.

```go
import "github.com/b4ck5p4c3/vetted"

d := vetted.New(
    vetted.WithTimeout(5*time.Second),
    vetted.WithMaxCost(vetted.CostSmall), // skip the HTML scrapers
    vetted.WithTracer(myTracer),          // optional Sentry or OTEL hook
)

res := d.Discover(ctx)
log.Printf("v4=%v v6=%v", res.V4, res.V6)
```

`Discover` returns a `Result` that carries both addresses, the name of
the endpoint that answered each family, the per-family error, and a log
of every attempt. Either address can be nil when no endpoint resolves
that family from the current network.

A long-lived resolver keeps a `Latest()` snapshot fresh and lets a
network-change callback force an off-cycle refresh.

```go
go d.Run(ctx, 15*time.Minute)

// from a mobile NWPathMonitor or ConnectivityManager callback:
d.Trigger()

// read the most recent result without starting a new cycle:
res := d.Latest()
```

`Run` blocks until the context is cancelled. `Trigger` is non-blocking
and coalesces, so a noisy callback queues at most one extra cycle.

### Custom endpoints

`WithPriorityEndpoints` registers probes that run before the built-in
defaults on every cycle, so a caller's preferred STUN or TURN server
wins and the defaults become a fallback.

```go
d := vetted.New(
    vetted.WithPriorityEndpoints(
        vetted.Endpoint{
            Name: "my-stun", Family: vetted.Any, Cost: vetted.CostMinimal,
            Prober: &vetted.STUNProbe{Addr: "stun.example.ru:3478"},
        },
    ),
)
```

`WithEndpoints` replaces the default set entirely. The two compose.
`WithEndpoints` sets the base, and `WithPriorityEndpoints` layers a
preferred set on top of it.

### Skipping IPv6

When the host has no IPv6, `WithFamilies(vetted.V4)` skips the v6 race
so the v6-only-host dial timeout never dominates a cycle.

```go
d := vetted.New(vetted.WithFamilies(vetted.V4))
res := d.Discover(ctx) // res.V6 stays nil, no v6 attempts run
```

## Egress matters

The default set is tuned for use from inside the RU mobile segment under
active filtering, and the egress decides which endpoints answer. From a
filtered RU network the marketplace and STUN probes resolve while the
lamoda probes fail. From a foreign or VPN egress the lamoda probes
resolve while avito and wildberries return an antibot page with no IP.

Two endpoint fields document this. `Endpoint.OptionalFrom` names the
egress under which an endpoint is expected to fail, and
`Endpoint.FilteredReachable` marks the endpoints verified to resolve
under RU filtering. The library does not act on either field. Both ride
through to the tracer on every attempt, so a dashboard can separate a
documented expected failure from a real regression. Filter alerting on
`Attempt.Endpoint.OptionalFrom != ""` to drop the expected noise.

## How it works

- **Cost-based selection** orders every cycle. Each `Endpoint` carries a
  `Cost` that approximates its response size in bytes. Endpoints of
  equal Cost race in parallel as one tier, and tiers run cheap-first.
  The Discoverer hits an HTML landing page only after every cheaper API
  has failed. `WithMaxCost` drops endpoints above a byte budget for
  metered links.
- **Cancel-on-win** bounds the cycle. As soon as one tier member returns
  a valid IP, the Discoverer cancels the in-flight requests for the rest
  of the tier and returns. The winner's latency bounds the cycle rather
  than the slowest member's.
- **Family pinning** keeps the two races separate. Each requested family
  races in its own goroutine with a dialer pinned to tcp4 or tcp6. The
  `net.Dialer.Control` callback rejects an address of the wrong family,
  and the dialer moves on to the next resolver candidate. A v6-only host
  on a v4-only network fails fast, which is the correct signal for "no
  v6 here". An endpoint's `Family` reflects real v6 capability from an
  AAAA-record audit, so the v6 race runs only the four v6-capable
  endpoints.
- **A browser fingerprint** unlocks the antibot pages. The default HTTP
  clients use [enetx/surf](https://github.com/enetx/surf) with a Chrome
  JA3/JA4 TLS fingerprint and a matching User-Agent. The marketplace
  landing pages return an antibot interstitial without it.
- **Pluggable transports** sit behind the `Prober` interface.
  `HTTPProbe` fetches a URL and extracts the IP with a `Parser`.
  `STUNProbe` reads the reflexive address from a STUN Binding response
  over TCP. A caller adds a transport by implementing `Prober`.
- **A pluggable tracer** carries observability. `Tracer` is a four-method
  interface with a `NoopTracer` default. The Sentry or OpenTelemetry
  adapter lives in the calling code, which keeps the library free of
  those dependencies.

STUN runs over TCP because RU mobile carriers drop outbound UDP to STUN
ports. `stun.rtc.yandex.net:3478` and the six VK STUN IP literals on
port 19302 answer over TCP from both RU and foreign egress, which makes
STUN the most reliable backstop.

## Default endpoints

Endpoints are listed in selection order. The Discoverer tries the lowest
Cost first and races endpoints of equal Cost in parallel. A `Family` of
`Any` runs in both races, and `V4` or `V6` runs in one. Cost is the
approximate response size in bytes, except for litres, where the `HEAD`
request strips the body to roughly 600 bytes.

| Name | Family | Cost | Probe | Notes |
| --- | --- | --- | --- | --- |
| qms | V4 | 50 | HTTP `JSONKey("ip")` | needs an `X-Api-Key` header |
| rt-speedtest | V4 | 50 | HTTP `JSONKey("ip")` | needs an `X-Api-Key` header |
| ipinfo | V4 | 50 | HTTP `JSONKey("ip")` | full geo JSON, times out on RU mobile, kept for non-RU egress |
| reg-speedtest | V4 | 50 | HTTP `JSONKey("ip")` | returns `{"ip":"...","success":true}` |
| start-proxycheck | V4 | 50 | HTTP `JSONKey("ip")` | apikey baked into the URL |
| yandex-stun | Any | 50 | STUN over TCP | egress-independent and the fastest reliable probe, the v6 path is AAAA-derived |
| alfabank | V4 | 50 | HTTP `Regex` | 404 JSON echoes the IP in a Russian message, resolves from foreign egress and misses from RU mobile |
| yandex-v4 | V4 | 50 | HTTP `JSONQuoted()` | v4-only host |
| yandex-v6 | V6 | 50 | HTTP `JSONQuoted()` | v6-only host |
| mail-ip | V4 | 50 | HTTP `JSONKey("ipAddress")` | JSONP-wrapped body |
| lamoda-information-get | V4 | 50 | HTTP `JSONKey("ip")` | `POST {}`, 403 with `data.ip`, resolves from foreign or VPN egress only |
| lamoda-topmenu-flexible | V4 | 50 | HTTP `JSONKey("ip")` | `POST {}`, sibling of lamoda-information-get |
| vk-stun-1..6 | V4 | 100 | STUN over TCP | VK STUN pool on port 19302, IP literals that may rotate |
| lamoda-vpn-error | V4 | 194 | HTTP `JSONKey("ip")` | 403 with `data.ip`, resolves from foreign or VPN egress only |
| litres | V4 | 500 | HTTP `Cookie("__ddg9_")` | DDoS-Guard echoes the IP in a cookie, uses `HEAD` so no body transfers |
| 2gis-antibot | V4 | 1411 | HTTP `Regex` | 403 antibot page echoes the IP |
| wildberries | Any | 1600 | HTTP `HTMLAttr("data-req-ip")` | HTTP 498 antibot page carries the IP, foreign egress returns 451 |
| mail-speedtest | V4 | 6900 | HTTP `Regex` | small landing page |
| yandex-internet-v4 | V4 | 114200 | HTTP `Regex` | parses `"v4"` from the page state JSON |
| yandex-internet-v6 | V6 | 114200 | HTTP `Regex` | parses `"v6"` from the same page state JSON |
| ivi | V4 | 300000 | HTTP `JSONKey("ip")` | 748 KB landing, IP near byte 266000 |
| tbank | V4 | 1770000 | HTTP `JSONKey("remoteAddress")` | IP near byte 255000, inside the 256 KB read cap |
| avito | V4 | 4000000 | HTTP `JSONKey("ip")` | 2.8 to 3.3 MB body, IP near the tail, foreign egress returns a 403 antibot page, a last-resort backstop |

## Live smoke test

A `live` build tag guards an opt-in test that hits every default
endpoint over the real network from the current egress and prints a
status matrix. The normal `go test` stays hermetic.

```
go test -tags=live -timeout=120s -v -run TestLive_AllDefaultEndpoints .
```

The test passes when at least five endpoints across both families
resolve an IP, which tolerates a transient antibot flake while still
catching a broad regression such as a parser breaking after an upstream
redesign.

## License

MIT plus the Beer-Ware clause (Revision 42). See [LICENSE](LICENSE).
