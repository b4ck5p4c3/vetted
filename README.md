# vetted

Public IP discovery via services on the Russian network allowlist.

Generic "echo my IP" services are easy to block; the endpoints in
this library's default set are large RU commercial sites (banks,
marketplaces, search engines) that the network filter actively
wants reachable — so they remain useful probes inside the RU
segment when generic providers do not.

## Status

Scaffolded. Half the default endpoints are TODO-tagged for live
verification of (a) response parser and (b) measured byte cost.
Open `endpoint.go` for the list.

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
  cheap-first sequentially. HTML landing pages (50KB+) only get
  hit when every cheap API has failed.
- **V4 + V6 in parallel.** Two dialer-pinned HTTP clients run
  independent races per family. A v4 result and v6 result land
  on the scope as separate values; either or both may be unset
  depending on host connectivity.
- **Browser fingerprint.** Default HTTP clients use
  [enetx/surf](https://github.com/enetx/surf) with Chrome
  Impersonate — JA3/JA4 TLS fingerprint + matching User-Agent.
  Necessary for the HTML landing pages (wildberries, tbank,
  avito) that would otherwise return an antibot interstitial.
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

API (race in parallel, `CostMinimal`):

| Name | URL | Notes |
|---|---|---|
| qms | `www.qms.ru/api/asn_provider/ip` | `X-Api-Key` header |
| rt-speedtest | `speedtest.rt.ru/api/asn_provider/ip` | `X-Api-Key` header |
| ipinfo | `ipinfo.io/json` | full geo JSON |
| reg-speedtest | `speedtest.reg.ru/detect_ip_info` | TODO verify shape |
| alfabank | `alfabank.ru/api/v2/geo-facade/geo/ip` | TODO verify shape |
| yandex-v4 | `ipv4-internet.yandex.net/api/v0/ip` | v4-only host |
| yandex-v6 | `ipv6-internet.yandex.net/api/v0/ip` | v6-only host |
| mail-ip | `ip.mail.ru/ip.html` | tiny HTML; TODO verify markup |

HTML landing pages (fall-through tiers, Cost = measured size):

| Name | URL | Notes |
|---|---|---|
| yandex-internet | `yandex.ru/internet/` | embeds IP in JSON state |
| mail-speedtest | `speedtest.mail.ru/` | TODO live-check |
| wildberries | `wildberries.ru/` | `data-req-ip` attribute |
| tbank | `tbank.ru` | TODO live-check |
| avito | `avito.ru/` | TODO live-check |

## License

TBD.
