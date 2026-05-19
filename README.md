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

| Name | URL | Parser | Notes |
|---|---|---|---|
| qms | `www.qms.ru/api/asn_provider/ip` | `JSONKey("ip")` | `X-Api-Key` header |
| rt-speedtest | `speedtest.rt.ru/api/asn_provider/ip` | `JSONKey("ip")` | `X-Api-Key` header |
| ipinfo | `ipinfo.io/json` | `JSONKey("ip")` | full geo JSON |
| reg-speedtest | `speedtest.reg.ru/detect_ip_info` | `JSONKey("ip")` | `{"ip":"...","success":true}` |
| start-proxycheck | `api.start.ru/account/proxycheck` | `JSONKey("ip")` | apikey query param baked into URL |
| yandex-v4 | `ipv4-internet.yandex.net/api/v0/ip` | `JSONQuoted()` | v4-only host |
| yandex-v6 | `ipv6-internet.yandex.net/api/v0/ip` | `JSONQuoted()` | v6-only host |
| mail-ip | `ip.mail.ru/ip.html` | `JSONKey("ipAddress")` | JSONP wrapper |

HTML landing pages (fall-through, Cost = measured body size in bytes):

| Name | URL | Parser | Cost | Notes |
|---|---|---|---|---|
| yandex-internet-v4 | `yandex.ru/internet/` | `Regex("v4":"...")` | 114200 | v4 race only |
| yandex-internet-v6 | `yandex.ru/internet/` | `Regex("v6":"...")` | 114200 | v6 race only |
| mail-speedtest | `speedtest.mail.ru/` | `Regex("IP: ...")` | 6900 | small landing |
| wildberries | `www.wildberries.ru/` | `HTMLAttr("data-req-ip")` | 1600 | antibot variant from foreign IP; full landing larger inside RU (unmeasured) |
| tbank | `www.tbank.ru` | `JSONKey("remoteAddress")` | 1770000 | IP sits at byte ~255 KB, just inside the 256 KB response cap |
| litres | `www.litres.ru/` | `Cookie("__ddg9_")` | 256000 | DDoS-Guard echoes client IP in `__ddg9_` cookie; body downloaded (~557 KB, capped at 256 KB) but not parsed — header-only short-circuit is a future optimisation |
| lamoda-vpn-error | `www.lamoda.ru/api/v1/recommendations/section` | `JSONKey("ip")` | 194 | 403 with `{"code":10403,"data":{"ip":"..."}}` — opt-in via `AcceptStatus: [200, 403]` |
| 2gis-antibot | `2gis.ru/` | `Regex(REQUEST-IP IP:...)` | 1411 | 403 antibot landing echoes IP in `<p id="REQUEST-IP">`; `AcceptStatus: [200, 403]` |

Removed during verification:

- **alfabank** (`alfabank.ru/api/v2/geo-facade/geo/ip`) — 307s to
  itself with a `set-cookie: spid=...` antibot cookie pair on every
  hit and expects a JS-set companion cookie before answering with
  the geo JSON. Stateless clients (curl, surf without a cookie jar
  + JS engine) loop forever. Not viable as a stateless probe.
- **avito** (`www.avito.ru/`) — from foreign egress returns a 27 KB
  antibot page (`Доступ ограничен: проблема с IP`) with no IP
  echoed; from inside RU the IP is reported to sit ~1 MB into the
  landing, past the 256 KB response cap. Either way not workable
  from this environment.
- **ivi.tv** (`www.ivi.tv/`) — 731 KB landing with the IP at byte
  266502 (`"ip":"..."` inside an ABTest state block). 4 KB past the
  256 KB cap; one occurrence in the body so a higher per-endpoint
  cap is the only way to keep it. Skipped for now.
- **lamoda /information/get + /cms/topmenu_flexible** — 400 errors
  with 65 B bodies that don't echo the IP. Only the
  `/recommendations/section` endpoint of the lamoda API echoes IP in
  its 403 body (kept as `lamoda-vpn-error`).

## Status

All TODO-tagged endpoints have been live-verified; parsers and
costs above reflect measured body shape and size. Two endpoints
(alfabank, avito) were removed during verification — see the
"Removed during verification" section above.

## License

TBD.
