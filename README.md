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
| alfabank         | `alfabank.ru/api/v2/geo-facade/geo/ip`| `Regex(IP X.X.X.X)`    | 404 JSON `"по IP <ip> нет информации"` (Russian message); ServicePipe one-hop 307+cookie antibot; `AcceptStatus: [200, 404]`; needs HTML `Accept` header |
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
| wildberries             | `www.wildberries.ru/`                          | `HTMLAttr("data-req-ip")`  | 1600    | antibot variant from foreign IP; full landing larger inside RU (unmeasured)                                                                                      |
| ivi                     | `www.ivi.tv/`                                  | `JSONKey("ip")`            | 300000  | 748 KB landing; single `"ip":"..."` at byte ~266 K — `MaxBytes: 300_000` to reach it                                                                             |
| avito                   | `www.avito.ru/`                                | `JSONKey("ip")`            | 1000000 | 985 KB landing from RU egress; IP near byte ~958 K — needs `MaxBytes: 1_000_000`. Foreign egress returns 27 KB 403 antibot → parser_miss, soft fail             |
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
