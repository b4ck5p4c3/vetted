package vetted

import "fmt"

// knownMethods is the allowlist for Endpoint.Method validation.
// Anything outside this set (or empty) is rejected by Validate so a
// typo doesn't silently turn into a GET in attempt().
var knownMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"PATCH":   {},
	"DELETE":  {},
	"HEAD":    {},
	"OPTIONS": {},
}

// Family is the IP version an endpoint can answer for. A v4-only
// hostname (A record only, like ipv4-internet.yandex.net) is V4;
// a v6-only hostname is V6; dual-stack DNS that works for either
// family is Any.
type Family string

const (
	V4  Family = "v4"
	V6  Family = "v6"
	Any Family = "any"
)

// Cost is the rough response payload size in bytes for one
// successful call to an endpoint. The Discoverer prefers cheap
// endpoints; expensive endpoints (HTML landing pages 50KB+) only
// get hit when the cheap tier has failed. Callers on metered
// connections cap eligibility with WithMaxCost.
//
// Selection semantics within Discover:
//
//   - endpoints with the SAME Cost form one tier and race in
//     parallel — first to return a valid IP wins;
//   - tiers are tried in ASCENDING Cost order — the next tier
//     only fires if every endpoint in the previous tier failed.
//
// So bucketed values like the constants below give you parallelism
// inside a price band; unique per-endpoint byte counts degrade to
// pure sequential fallback. Pick whichever fits the use case.
// Any positive value is legal; the Cost type is just `int`.
type Cost int

const (
	// CostMinimal: bare JSON like `{"ip":"..."}` or `"<ip>"` —
	// ~20–100 bytes on the wire.
	CostMinimal Cost = 50
	// CostSmall: small JSON wrapper with metadata (asn, country,
	// city, ...) on the order of a few hundred bytes.
	CostSmall Cost = 500
	// CostMedium: large JSON or small HTML — a few KB.
	CostMedium Cost = 5_000
	// CostHigh: full HTML landing page (antibot, marketplaces). The
	// only reason to use a CostHigh endpoint is that everything
	// cheaper has failed.
	CostHigh Cost = 50_000
)

// Endpoint is one IP-echo probe: transport-agnostic metadata (Name,
// Family, Cost, OptionalFrom) plus a Prober that performs the actual
// transport-specific fetch. The Discoverer owns the family race,
// cost tiering, cancellation and tracing; the Prober owns "how to
// get the IP" — see HTTPProbe and STUNProbe.
type Endpoint struct {
	// Name is the short identifier used in logs and span tags (no
	// spaces). Must be unique within a Discoverer's endpoint set.
	Name string

	// Family is the IP version this endpoint can answer for. Any
	// means it is raced in both the v4 and v6 cycles.
	Family Family

	// Cost approximates the response payload size in bytes; the
	// Discoverer races equal-Cost endpoints in parallel and tries
	// cheaper tiers first. See the Cost constants.
	Cost Cost

	// Prober performs the transport-specific probe. Required.
	Prober Prober

	// OptionalFrom, when non-empty, documents the egress condition
	// under which this endpoint is EXPECTED to fail. The library
	// does not act on it — failures still bubble up with their real
	// FailReason — but the annotation rides through to the Tracer
	// via Attempt.Endpoint.OptionalFrom so operator dashboards can
	// distinguish "real regression" from "documented expected
	// failure for this deployment's egress" and avoid alerting on
	// the latter.
	//
	// Values are free-form strings; conventional tags currently used
	// in DefaultEndpoints are "domestic-RU egress" (lamoda variants:
	// 307-loop on RU IPs, only return IP-bearing 403 on VPN /
	// foreign) and "foreign egress" (avito / wildberries: full
	// landing only served to RU IPs; foreign IPs get an antibot
	// stub with no IP echo). Mobile-RU deployments will see lamoda
	// fail every cycle — that is the documented behaviour, not a
	// regression.
	OptionalFrom string
}

// Validate returns an error if the endpoint config is incomplete.
// Transport-specific checks are delegated to the Prober.
func (e Endpoint) Validate() error {
	if e.Name == "" {
		return fmt.Errorf("vetted: endpoint missing Name")
	}
	if e.Family != V4 && e.Family != V6 && e.Family != Any {
		return fmt.Errorf("vetted: endpoint %q has invalid Family %q", e.Name, e.Family)
	}
	if e.Cost <= 0 {
		return fmt.Errorf("vetted: endpoint %q has non-positive Cost %d", e.Name, e.Cost)
	}
	if e.Prober == nil {
		return fmt.Errorf("vetted: endpoint %q missing Prober", e.Name)
	}
	return e.Prober.Validate(e.Name)
}

// vkSTUN builds one entry of the VK STUN fallback pool: a v4
// STUN-over-TCP probe at Cost 100 (just above the primary CostMinimal
// tier). See the pool comment in DefaultEndpoints.
func vkSTUN(name, addr string) Endpoint {
	return Endpoint{Name: name, Family: V4, Cost: 100, Prober: &STUNProbe{Addr: addr}}
}

// DefaultEndpoints is the curated list of "RU allowlist" probes.
// Two physical tiers:
//
//   - cheap API + STUN (tiny JSON / a STUN binding): all marked
//     CostMinimal because the difference between 20 and 500 bytes
//     does not justify cost-tiering overhead; they race in parallel
//     and the fastest wins;
//   - fall-through endpoints (kilobytes-to-megabytes of antibot /
//     marketplace HTML): each has Cost set to the **measured**
//     response size, established via a one-shot live fetch during
//     curation. The Discoverer only falls through to these when the
//     cheap tier has failed.
//
// Every entry's Cost / Parser / transport choice is live-verified;
// per-endpoint rationale (and which fail from which egress) is in the
// comments below and the README tables. The Discoverer re-sorts by
// Cost at construction time so manual overrides still get correct
// priority order.
var DefaultEndpoints = []Endpoint{
	// ── API endpoints — CostMinimal, race in parallel ────────────
	{
		Name:   "qms",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{
			URL:     "https://www.qms.ru/api/asn_provider/ip",
			Headers: map[string]string{"X-Api-Key": "c2852614b821db79e99218cce8d32b3d"},
			Parser:  JSONKey("ip"),
		},
	},
	{
		// Live-verified: returns `{"ip":"..."}` (21 bytes) with the
		// same /api/asn_provider/ip shape as qms.
		Name:   "rt-speedtest",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{
			URL:     "https://speedtest.rt.ru/api/asn_provider/ip",
			Headers: map[string]string{"X-Api-Key": "f85f12b942ab0a8818eb66d64b244ee5"},
			Parser:  JSONKey("ip"),
		},
	},
	{
		Name:   "ipinfo",
		Family: Any,
		Cost:   CostMinimal,
		// Documented: {"ip":"...","hostname":"...","city":"...",...}.
		// Generic provider — measured to TIME OUT on RU mobile
		// (Beeline LTE); kept for non-RU / WiFi egress.
		Prober: &HTTPProbe{URL: "https://ipinfo.io/json", Parser: JSONKey("ip")},
	},
	{
		// Live-verified: `{"ip":"...","success":true}` (37 bytes).
		Name:   "reg-speedtest",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{URL: "https://speedtest.reg.ru/detect_ip_info", Parser: JSONKey("ip")},
	},
	{
		// Live-verified: 548 B body with `"ip":"..."` plus
		// proxy / geo metadata. Plain 200 / JSON shape.
		Name:   "start-proxycheck",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{
			URL:    "https://api.start.ru/account/proxycheck?apikey=a20b12b279f744f2b3c7b5c5400c4eb5",
			Parser: JSONKey("ip"),
		},
	},
	{
		// STUN-over-TCP to Yandex's RTC STUN. Live-verified from both
		// foreign and Beeline-LTE egress: returns the reflexive
		// public IP in XOR-MAPPED-ADDRESS. Transport is TCP because RU
		// mobile carriers drop outbound UDP to STUN ports wholesale
		// (only UDP/53 passes); stun.yandex.ru / google / okcdn fail
		// entirely. Unlike the HTTP probes this does not depend on
		// egress direction (works in-RU and abroad) — the primary
		// STUN probe and a stable backstop for the HTTP tier.
		Name:   "yandex-stun",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &STUNProbe{Addr: "stun.rtc.yandex.net:3478"},
	},
	// VK STUN pool (AS47764, VK-AS). All six live-verified answering
	// STUN over TCP on :19302 from Beeline LTE, returning the correct
	// mobile reflexive IP; UDP times out (carrier). Cost 100 puts them
	// in a fallback tier just above the primary CostMinimal tier — they
	// fire only if every primary probe (including yandex-stun) failed,
	// before the expensive HTML scrapers, and race among themselves.
	// IP literals, not hostnames: VK has no published STUN hostname and
	// may rotate these addresses, so treat the set as best-effort and
	// re-verify with the live smoke test if STUN coverage regresses.
	// Family V4 — these are v4 literals; a v6 race skips them.
	vkSTUN("vk-stun-1", "91.231.135.136:19302"),
	vkSTUN("vk-stun-2", "95.163.34.130:19302"),
	vkSTUN("vk-stun-3", "90.156.236.100:19302"),
	vkSTUN("vk-stun-4", "91.231.135.153:19302"),
	vkSTUN("vk-stun-5", "193.203.43.14:19302"),
	vkSTUN("vk-stun-6", "193.203.43.39:19302"),
	{
		// Live-verified: /api/v2/geo-facade/geo/ip returns HTTP 404
		// with `{"status":"NOT_FOUND","message":"Город не найден,
		// т.к по IP <ip> нет информации в системе"}` (137 B). The
		// IP is echoed verbatim in the Russian message as the
		// rejection reason for "no geo data for this address".
		//
		// Antibot dance is a one-hop ServicePipe replay: the first
		// request gets HTTP 307 to the same URL with a `set-cookie:
		// spid=...; spsc=...` pair; the surf client's Session()
		// cookie jar replays with the cookies and the second hop
		// answers 404 + body. Round trip ~1-3s end-to-end which
		// loses the race against sub-second API endpoints but pulls
		// through as a backstop when the cheap tier is blocked.
		//
		// The bare path (no `?detect_ip=true` query) is a clean
		// one-hop replay; the detect_ip variant 307s into a JS-cookie
		// flow stateless clients cannot complete. AcceptStatus opts
		// the 404 past the 2xx gate; the matching Accept header keeps
		// ServicePipe on the HTML-replay branch rather than serving
		// the JSON "406 Not Acceptable" path. NOTE: from RU mobile
		// the live response shape differs and the parser misses —
		// works cleanly from foreign egress.
		Name:   "alfabank",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{
			URL: "https://alfabank.ru/api/v2/geo-facade/geo/ip",
			Headers: map[string]string{
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			},
			AcceptStatus: []int{200, 404},
			Parser:       Regex(`IP\s+((?:\d{1,3}\.){3}\d{1,3})`),
		},
	},
	{
		Name:   "yandex-v4",
		Family: V4,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{URL: "https://ipv4-internet.yandex.net/api/v0/ip", Parser: JSONQuoted()},
	},
	{
		Name:   "yandex-v6",
		Family: V6,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{URL: "https://ipv6-internet.yandex.net/api/v0/ip", Parser: JSONQuoted()},
	},
	{
		// Live-verified: JSONP-shaped body
		// `(none)({"ipAddress": "...", "xForwardedFor": "(none)"})`
		// — 65 bytes. JSONKey("ipAddress") matches inside the
		// JSONP wrapper just like a plain JSON object.
		Name:   "mail-ip",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{URL: "https://ip.mail.ru/ip.html", Parser: JSONKey("ipAddress")},
	},

	// ── Fall-through endpoints — Cost = measured response bytes ───
	{
		// Live-verified at ~114 KB. The page embeds state JSON
		// containing two relevant keys: `"ip":"Нюрнберг"` (a CITY
		// name, leftover from a different schema branch) and
		// `"v4":"159.195.6.55"` (the actual IP, nested inside
		// `"ip":{"v4":...,"v6":null}`). We parse `"v4"` for the V4
		// race and split out a separate V6 entry below.
		Name:   "yandex-internet-v4",
		Family: V4,
		Cost:   114200,
		Prober: &HTTPProbe{URL: "https://yandex.ru/internet/", Parser: Regex(`"v4"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"`)},
	},
	{
		// Same page; V6 race parses the `"v6":"..."` key from the
		// same state JSON. v6 is `null` on v4-only egress, so this
		// parser fails cleanly there.
		Name:   "yandex-internet-v6",
		Family: V6,
		Cost:   114200,
		Prober: &HTTPProbe{URL: "https://yandex.ru/internet/", Parser: Regex(`"v6"\s*:\s*"([0-9a-fA-F:]+)"`)},
	},
	{
		// Live-verified at ~6.9 KB. The IP is in a small markup
		// fragment `<p>IP: 1.2.3.4</p>` — match the literal prefix
		// to avoid catching the unrelated `120.0.0.0` user-agent
		// version that also appears in the page.
		Name:   "mail-speedtest",
		Family: Any,
		Cost:   6900,
		Prober: &HTTPProbe{URL: "https://speedtest.mail.ru/", Parser: Regex(`IP:\s*((?:\d{1,3}\.){3}\d{1,3})`)},
	},
	{
		// Live-verified: wildberries returns a small antibot-style
		// landing (~1.6 KB on foreign egress, larger inside RU) and
		// the requester IP sits in `data-req-ip="..."` on the root
		// <html> element. From foreign IPs the page comes back HTTP
		// 451 so the discoverer rejects it. Measured parser_miss from
		// RU mobile too (landing shape differs) — so OptionalFrom is
		// "foreign egress" but RU is not guaranteed either.
		Name:         "wildberries",
		Family:       Any,
		Cost:         1600,
		Prober:       &HTTPProbe{URL: "https://www.wildberries.ru/", Parser: HTMLAttr("data-req-ip")},
		OptionalFrom: "foreign egress",
	},
	{
		// Live-verified: litres is fronted by DDoS-Guard, which
		// injects a `__ddg9_=<client-ip>` Set-Cookie alongside
		// `__ddg8_`/`__ddg10_`/`__ddg1_` siblings. The IP rides in
		// the HEADER, not the body — so we send HEAD instead of GET
		// and DDoS-Guard still echoes the cookie in the response
		// headers (live-verified: identical __ddg9_ value on HEAD
		// vs GET). Saves ~256 KB per cycle that this endpoint fires.
		// Cost CostSmall keeps it out of the parallel API race; it
		// loses cleanly to sub-100ms JSON endpoints on latency.
		Name:   "litres",
		Family: Any,
		Cost:   CostSmall,
		Prober: &HTTPProbe{URL: "https://www.litres.ru/", Method: "HEAD", Parser: Cookie("__ddg9_")},
	},
	{
		// Live-verified: lamoda's recommendations API returns HTTP
		// 403 with `{"code":10403,"message":"...","data":{"ip":"..."}}`
		// (194 B) on requests from VPN / non-RU IPs — the IP is
		// echoed back as part of the "VPN detected" payload.
		//
		// EGRESS-DIRECTION CAVEAT (every lamoda-* probe): the
		// 403-with-IP only fires when lamoda classifies the egress as
		// VPN / foreign. From a domestic RU IP the URL 307-loops with
		// a "blank\n" body and never reaches 200/403 — measured
		// non_2xx on Beeline LTE. So lamoda SUCCEEDS abroad / behind
		// a VPN and FAILS on RU mobile; OptionalFrom flags it.
		Name:   "lamoda-vpn-error",
		Family: Any,
		Cost:   194,
		Prober: &HTTPProbe{
			URL:          "https://www.lamoda.ru/api/v1/recommendations/section",
			Parser:       JSONKey("ip"),
			AcceptStatus: []int{200, 403},
		},
		OptionalFrom: "domestic-RU egress",
	},
	{
		// Live-verified: 2gis returns a 403 antibot landing on
		// every stateless request (~1.4 KB) with the requester
		// IP echoed as `<p id="REQUEST-IP">IP: <ip></p>`. The
		// 200 happy path from inside RU has a different shape and
		// the parser misses cleanly — accepting both codes is safe
		// because parse failure is a soft error.
		Name:   "2gis-antibot",
		Family: Any,
		Cost:   1411,
		Prober: &HTTPProbe{
			URL:          "https://2gis.ru/",
			Parser:       Regex(`REQUEST-IP[^<]*IP:\s*((?:\d{1,3}\.){3}\d{1,3})`),
			AcceptStatus: []int{200, 403},
		},
	},
	{
		// Live-verified at ~1.77 MB. The IP appears in a JSON
		// island as `"remoteAddress":"..."` at byte ~255200 — just
		// inside the 256 KB response cap. Fragile: a page
		// reorganisation that pushes the island past 256 KB silently
		// breaks this (parser_miss). On RU mobile the 1.77 MB body
		// often times out within the cycle budget.
		Name:   "tbank",
		Family: Any,
		Cost:   1770000,
		Prober: &HTTPProbe{URL: "https://www.tbank.ru", Parser: JSONKey("remoteAddress")},
	},
	{
		// Live-verified from both foreign and domestic-RU egress.
		// Domestic RU: HTTP 200, 985 KB landing, IP near byte ~958 K
		// — needs MaxBytes ~1_000_000 to reach. Foreign egress: HTTP
		// 403, 27 KB antibot interstitial, no IP echo → parser_miss.
		// Cost is the full 1_000_000 B on purpose: callers cap
		// eligibility with WithMaxCost; any cap < 1_000_000 drops it.
		Name:   "avito",
		Family: Any,
		Cost:   1_000_000,
		Prober: &HTTPProbe{
			URL:      "https://www.avito.ru/",
			Parser:   JSONKey("ip"),
			MaxBytes: 1_000_000,
		},
		OptionalFrom: "foreign egress",
	},
	{
		// Live-verified: 748801 B body with a single `"ip":"..."`
		// token at byte offset 266202. MaxBytes=300_000 gives a
		// ~33 KB margin above the IP position; Cost matches MaxBytes
		// because that is the byte volume actually pulled.
		Name:   "ivi",
		Family: Any,
		Cost:   300_000,
		Prober: &HTTPProbe{URL: "https://www.ivi.tv/", Parser: JSONKey("ip"), MaxBytes: 300_000},
	},
	{
		// Live-verified: POST {} to /api/v1/information/get returns
		// 403 with the same VPN-detected shape lamoda-vpn-error uses
		// (`{"code":10403,"data":{"ip":"<ip>"},...}`, 194 B). Plain
		// GET 400s — needs Method + Body. Same egress caveat.
		Name:   "lamoda-information-get",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{
			URL:          "https://www.lamoda.ru/api/v1/information/get",
			Method:       "POST",
			Body:         []byte(`{}`),
			Headers:      map[string]string{"Content-Type": "application/json"},
			Parser:       JSONKey("ip"),
			AcceptStatus: []int{200, 403},
		},
		OptionalFrom: "domestic-RU egress",
	},
	{
		// Live-verified: same shape as lamoda-information-get — POST
		// {} → 403 with `data.ip`. Sibling so one flapping API path
		// doesn't knock out the whole lamoda set. Same egress caveat.
		Name:   "lamoda-topmenu-flexible",
		Family: Any,
		Cost:   CostMinimal,
		Prober: &HTTPProbe{
			URL:          "https://www.lamoda.ru/api/v1/cms/topmenu_flexible",
			Method:       "POST",
			Body:         []byte(`{}`),
			Headers:      map[string]string{"Content-Type": "application/json"},
			Parser:       JSONKey("ip"),
			AcceptStatus: []int{200, 403},
		},
		OptionalFrom: "domestic-RU egress",
	},
}
