# vetted

Public IP discovery via services on the Russian network allowlist.

Generic "echo my IP" services are easy to block; the endpoints in
this library's default set are large RU commercial sites (banks,
marketplaces, search engines) that the network filter actively
wants reachable — so they remain useful probes inside the RU
segment when generic providers do not.

## Usage

```go
import "github.com/b4ck5p4c3/vetted"

d := vetted.New(
    vetted.WithTimeout(5*time.Second),
    vetted.WithMaxCost(vetted.CostSmall), // skip HTML scrapers
    vetted.WithTracer(myTracer),          // optional Sentry/OTEL hook
)

res := d.Discover(ctx)
log.Printf("v4=%v v6=%v", res.V4, res.V6)
```

Or run continuously and let `Trigger()` fire off-cycle refreshes
from a network-change callback:

```go
go d.Run(ctx, 15*time.Minute)

// elsewhere — mobile NWPathMonitor / ConnectivityManager change:
d.Trigger()

// latest snapshot without firing a new cycle:
res := d.Latest()
```

Pass your own preferred probes (tried before the built-in defaults,
which become a fallback) — e.g. STUN servers you trust or fetched
from a live config:

```go
d := vetted.New(
    vetted.WithPriorityEndpoints(
        vetted.Endpoint{
            Name: "my-stun", Family: vetted.Any, Cost: vetted.CostMinimal,
            Prober: &vetted.STUNProbe{Addr: "stun.example.ru:3478"}, // TCP
        },
    ),
)
```

## Design

- **Cost-based selection.** Each `Endpoint` carries a `Cost`
  approximating its response size in bytes. Endpoints with equal
  Cost race in parallel within one tier; tiers are tried
  cheap-first sequentially. HTML landing pages only get hit when
  every cheap API has failed.
- **Cancel-on-win.** As soon as one tier member returns a valid IP,
  the in-flight requests for the rest of the tier get
  context-cancelled and the cycle returns. The losers' Attempts
  still get drained so Tracer sees them (with `FailReason=canceled`),
  but the cycle is bounded by the WINNER's latency rather than the
  slowest tier member's. On a filtered mobile RU network this
  routinely shaves multiple seconds off a cycle.
- **HEAD short-circuit.** Endpoints whose Parser only reads response
  headers (Cookie parser on litres) set `Method: "HEAD"`. The
  Discoverer skips the body read entirely, saving 256 KB per
  litres-firing cycle.
- **V4 + V6 in parallel.** Two dialer-pinned HTTP clients run
  independent races per family. A v4 result and v6 result land
  on the scope as separate values; either or both may be unset
  depending on host connectivity.
- **Browser fingerprint.** Default HTTP clients use
  [enetx/surf](https://github.com/enetx/surf) with Chrome
  Impersonate — JA3/JA4 TLS fingerprint + matching User-Agent.
  Necessary for the HTML landing pages (wildberries, tbank) that
  would otherwise return an antibot interstitial.
- **Pluggable transports (`Prober`).** Each `Endpoint` carries a
  `Prober` that performs the transport-specific fetch; the Discoverer
  owns the race, cost tiering, family enforcement and tracing. Two
  ship: `HTTPProbe` (fetch a URL, extract the IP with a `Parser`) and
  `STUNProbe` (STUN Binding Request over TCP). A caller can add its
  own transport — e.g. a TURN host parsed out of a live OK.ru call
  config — by implementing `Prober` and passing it via `WithEndpoints`.
- **STUN over TCP.** `STUNProbe` reads the reflexive address from
  XOR-MAPPED-ADDRESS. Transport is TCP, not UDP: RU mobile carriers
  (measured on Beeline LTE) drop outbound UDP to STUN ports while
  passing TCP, so UDP STUN never answers. `stun.rtc.yandex.net:3478`
  (primary) and the six VK STUN IPs on `:19302` (AS47764, fallback
  pool) answer over TCP and are egress-independent (work in-RU and
  abroad) — the most reliable backstop, measured ~1.1s on Beeline LTE.
- **Priority endpoints.** `WithPriorityEndpoints(...)` registers
  probes tried *before* the whole default/base set every cycle — the
  caller's preferred STUN/TURN servers (e.g. ones fetched from a live
  call config) win over the built-in defaults, which become a
  fallback. The priority block is cost-tiered among itself and
  precedes the base block regardless of Cost. Composes with
  `WithEndpoints` (which replaces the base set).
- **Pluggable tracer.** `Tracer` is a small interface
  (CycleStart/End, AttemptStart/End) with a `NoopTracer` default.
  Sentry / OpenTelemetry adapters live in the calling code, not
  here — keeps this library dependency-light.

## Family pinning mechanism

`net.Dialer.Control` runs per-connection-attempt with the resolved
literal IP. The Control callback rejects wrong-family addresses;
the dialer's built-in fallback then moves on to the next candidate
from the resolver result list. A v6-only hostname on a v4-only
host fails fast — which is the correct "no v6 here" signal.

## Default endpoints

API endpoints (`CostMinimal`, race in parallel):

| Name             | URL                                   | Parser                 | Notes                             |
| ---------------- | ------------------------------------- | ---------------------- | --------------------------------- |
| qms              | `www.qms.ru/api/asn_provider/ip`      | `JSONKey("ip")`        | `X-Api-Key` header                |
| rt-speedtest     | `speedtest.rt.ru/api/asn_provider/ip` | `JSONKey("ip")`        | `X-Api-Key` header                |
| ipinfo           | `ipinfo.io/json`                      | `JSONKey("ip")`        | full geo JSON                     |
| reg-speedtest    | `speedtest.reg.ru/detect_ip_info`     | `JSONKey("ip")`        | `{"ip":"...","success":true}`     |
| start-proxycheck | `api.start.ru/account/proxycheck`     | `JSONKey("ip")`        | apikey query param baked into URL |
| yandex-stun      | `stun.rtc.yandex.net:3478`            | `STUNProbe` (TCP)      | STUN Binding over TCP; egress-independent (works in-RU and abroad); fastest reliable probe (~1.1s on Beeline LTE). UDP STUN is dropped by RU mobile carriers — TCP only |
| vk-stun-1..6     | `{91.231.135.136, 95.163.34.130, 90.156.236.100, 91.231.135.153, 193.203.43.14, 193.203.43.39}:19302` | `STUNProbe` (TCP) | VK STUN pool (AS47764); `Cost: 100` fallback tier above the primary one — fires as a 6-way race only if every primary probe (incl. yandex-stun) failed. All live-verified over TCP/19302 from Beeline LTE; UDP blocked. IP literals (no published hostname) — may rotate |
| alfabank         | `alfabank.ru/api/v2/geo-facade/geo/ip`| `Regex(IP X.X.X.X)`    | 404 JSON `"по IP <ip> нет информации"` (Russian message); ServicePipe one-hop 307+cookie antibot; `AcceptStatus: [200, 404]`; needs HTML `Accept` header. parser_miss from RU mobile (response shape differs) |
| yandex-v4        | `ipv4-internet.yandex.net/api/v0/ip`  | `JSONQuoted()`         | v4-only host                      |
| yandex-v6        | `ipv6-internet.yandex.net/api/v0/ip`  | `JSONQuoted()`         | v6-only host                      |
| mail-ip          | `ip.mail.ru/ip.html`                  | `JSONKey("ipAddress")` | JSONP wrapper                     |

Fall-through endpoints (fire only after the CostMinimal API tier
fails; Cost ≈ measured response size in bytes, with litres an
exception at `CostSmall` because HEAD strips its body to ~600 B):

| Name                    | URL                                            | Parser                     | Cost    | Notes                                                                                                                                                            |
| ----------------------- | ---------------------------------------------- | -------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| yandex-internet-v4      | `yandex.ru/internet/`                          | `Regex("v4":"...")`        | 114200  | v4 race only                                                                                                                                                     |
| yandex-internet-v6      | `yandex.ru/internet/`                          | `Regex("v6":"...")`        | 114200  | v6 race only                                                                                                                                                     |
| mail-speedtest          | `speedtest.mail.ru/`                           | `Regex("IP: ...")`         | 6900    | small landing                                                                                                                                                    |
| wildberries             | `www.wildberries.ru/`                          | `HTMLAttr("data-req-ip")`  | 1600    | HTTP **498** WAF antibot status carries the IP in `data-req-ip="..."`; `AcceptStatus: [200, 498]`. Live-verified `ok` at ~350ms on Beeline LTE (filtered). Foreign egress is 451 with no IP |
| ivi                     | `www.ivi.tv/`                                  | `JSONKey("ip")`            | 300000  | 748 KB landing; single `"ip":"..."` at byte ~266 K — `MaxBytes: 300_000` to reach it                                                                             |
| avito                   | `www.avito.ru/`                                | `JSONKey("ip")`            | 4000000 | RU mobile: 200, `"ip":"..."` near the tail of a 2.8–3.3 MB body (offset varies run-to-run, measured 2.76 M / 3.28 M). `MaxBytes: 4_000_000` with margin over the largest body seen. Foreign: 403 antibot, no IP. Resolves under filtering but ~6–14 s + multiple MB — last-resort backstop, callers drop it with `WithMaxCost` |
| tbank                   | `www.tbank.ru`                                 | `JSONKey("remoteAddress")` | 1770000 | IP sits at byte ~255 KB, just inside the 256 KB response cap                                                                                                     |
| litres                  | `www.litres.ru/`                               | `Cookie("__ddg9_")`        | 500     | DDoS-Guard echoes client IP in `__ddg9_` Set-Cookie header; uses `Method: "HEAD"` so body is never transferred (~600 B headers per cycle). Sometimes drops the `__ddg9_` cookie on rate-limited requests — soft fail, falls through to next endpoint |
| lamoda-vpn-error        | `www.lamoda.ru/api/v1/recommendations/section` | `JSONKey("ip")`            | 194     | 403 with `{"code":10403,"data":{"ip":"..."}}` — `AcceptStatus: [200, 403]`. Foreign/VPN egress only — 307-loops from domestic RU IPs                             |
| lamoda-information-get  | `www.lamoda.ru/api/v1/information/get`         | `JSONKey("ip")`            | 50      | POST `{}` → same 403 / `data.ip` shape; needs `Method: "POST"` + `Body: []byte("{}")`. Same egress-direction caveat as lamoda-vpn-error                          |
| lamoda-topmenu-flexible | `www.lamoda.ru/api/v1/cms/topmenu_flexible`    | `JSONKey("ip")`            | 50      | POST `{}` → same 403 / `data.ip` shape; sibling probe. Same egress-direction caveat as lamoda-vpn-error                                                          |
| 2gis-antibot            | `2gis.ru/`                                     | `Regex(REQUEST-IP IP:...)` | 1411    | 403 antibot landing echoes IP in `<p id="REQUEST-IP">`; `AcceptStatus: [200, 403]`                                                                               |

Removed during verification:

- **alfabank `/api/v2/geo-facade/geo/ip?detect_ip=true`** — the
  detect_ip variant 307s into a JS-cookie flow that stateless clients
  cannot complete. Even with a cookie jar the upstream insists on a
  JS-set companion cookie that curl / surf can't synthesise. The
  bare path (no `detect_ip=true` query) does NOT exhibit this
  behaviour — it is the one-hop ServicePipe replay covered by the
  `alfabank` entry above. Earlier removal commentary applied to the
  detect_ip variant only.
- **STUN over UDP, and several STUN hostnames** — measured from
  Beeline LTE (USB-tethered host, mobile egress). UDP STUN is dropped
  wholesale by the carrier (only UDP/53 passes), so every STUN server
  times out on UDP — transport must be TCP. Over TCP,
  `stun.yandex.ru:3478` and `stun.l.google.com:19302` do not answer;
  only `stun.rtc.yandex.net:3478` and the six VK `:19302` IPs do
  (both kept). The OK.ru / okcdn WebRTC hosts (`videowebrtc.okcdn.ru`,
  `calls.okcdn.ru`, the rotating `maxvdNNN.okcdn.ru` pool) resolve but
  do not answer STUN on 3478/5349; their `:443` accepts TCP then drops
  raw STUN bytes (TLS-fronted TURN under auth, not open STUN). Not
  usable as stateless probes.

## Expected-failure annotations

`Endpoint.OptionalFrom` is a free-form string that documents the
egress under which an endpoint is *expected* to fail. The library
does not act on it — failures still bubble up with their real
`FailReason` — but the annotation rides through to the Tracer via
`Attempt.Endpoint.OptionalFrom` so operator dashboards can
distinguish documented expected failures from real regressions.

Currently set in `DefaultEndpoints`:

| Endpoint | OptionalFrom | Why |
|---|---|---|
| lamoda-vpn-error | `domestic-RU egress` | 403-with-IP only fires on VPN / foreign IPs; from a domestic RU phone the URL 307-loops |
| lamoda-information-get | `domestic-RU egress` | same |
| lamoda-topmenu-flexible | `domestic-RU egress` | same |
| avito | `foreign egress` | landing-page IP echo only on RU IPs; foreign gets a 27 KB antibot stub with no IP |
| wildberries | `foreign egress` | returns HTTP 451 from foreign IPs; full antibot landing only on RU |

Mobile-RU deployments will see the three lamoda entries fail every
cycle — that is documented expected behaviour, not a regression.
Foreign / dev-machine deployments will see avito and wildberries
fail the same way. Filter your alerting on
`Attempt.Endpoint.OptionalFrom != ""` to drop the noise.

`Endpoint.FilteredReachable` is the inverse, positive signal: a bool
marking endpoints live-verified to resolve from inside the RU mobile
segment **with filtering active** (the "БС" state this library exists
for), measured on Beeline LTE. A `FilteredReachable` endpoint failing
under filtering is a true regression worth alerting on; an unmarked
one failing there is expected. Currently marked: `qms`, `rt-speedtest`,
`start-proxycheck`, `yandex-stun`, `vk-stun-1..6`, `mail-ip`,
`yandex-internet-v4`, `mail-speedtest`, `ivi`, `wildberries`, `avito`
(the last two only after the 498 / 4 MB fixes below). NOT marked
(work only unfiltered, or echo the IP only from foreign / antibot
state): `ipinfo`, `reg-speedtest`, `yandex-v4`, `alfabank`, `litres`,
`tbank`, `2gis-antibot`, the lamoda probes.

## Live smoke test

Opt-in regression alarm that hits every default endpoint over the
real network from the current egress and prints a status matrix.
Off by default — guarded by the `live` build tag so the normal
`go test` stays hermetic. Run before merging an endpoint-table
change, or whenever you suspect upstream rot:

```
go test -tags=live -timeout=120s -v -run TestLive_AllDefaultEndpoints .
```

The test fails only if fewer than five endpoints across both
families resolve an IP — generous enough to tolerate transient
DDoS-Guard / antibot flakes (litres in particular reissues
`__ddg9_` per request and sometimes drops it), strict enough to
catch broad-spectrum regressions like a parser breaking after a
upstream redesign. Per-endpoint outcomes land in the matrix log
even on PASS so a reader can spot the one regressed entry without
re-running.

## Status

All listed endpoints have been live-verified; parsers and costs
above reflect measured body shape and size. The four endpoints
originally parked for follow-up (avito, ivi, lamoda /information/get,
lamoda /cms/topmenu_flexible) were re-verified with the new
per-endpoint `MaxBytes` / `Method` / `Body` plumbing and have been
added back to the default set. avito in particular carries an honest
`Cost: 1_000_000` so callers who cannot afford a megabyte per cycle
drop it with `WithMaxCost(CostMedium)` or similar. alfabank was
re-verified after the initial removal: the bare path (no
`?detect_ip=true`) does a clean one-hop ServicePipe replay and
echoes the IP in a 404 JSON message, so it is back in the API tier.

## License

MIT, plus the Beer-Ware clause (Revision 42). See [LICENSE](LICENSE).
