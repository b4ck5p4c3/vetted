package vetted

import "fmt"

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

// Endpoint describes one IP-echo service. Name is the short
// identifier used in logs and span tags (no spaces). Parser
// extracts the IP candidate from the response body; the Discoverer
// then validates with net.ParseIP and rejects family-mismatched
// candidates.
type Endpoint struct {
	Name    string
	URL     string
	Family  Family
	Cost    Cost
	Headers map[string]string
	Parser  Parser
}

// Validate returns an error if the endpoint config is incomplete.
// Useful for table-driven setup code.
func (e Endpoint) Validate() error {
	if e.Name == "" {
		return fmt.Errorf("vetted: endpoint missing Name")
	}
	if e.URL == "" {
		return fmt.Errorf("vetted: endpoint %q missing URL", e.Name)
	}
	if e.Parser == nil {
		return fmt.Errorf("vetted: endpoint %q missing Parser", e.Name)
	}
	if e.Family != V4 && e.Family != V6 && e.Family != Any {
		return fmt.Errorf("vetted: endpoint %q has invalid Family %q", e.Name, e.Family)
	}
	if e.Cost <= 0 {
		return fmt.Errorf("vetted: endpoint %q has non-positive Cost %d", e.Name, e.Cost)
	}
	return nil
}

// DefaultEndpoints is the curated list of "RU allowlist" probes.
// Two physical tiers:
//
//   - API endpoints (tiny JSON, single-digit-KB or smaller): all
//     marked CostMinimal because the difference between 20 bytes
//     and 500 bytes does not justify cost-tiering overhead; they
//     race in parallel and the fastest wins;
//   - HTML landing pages (kilobytes of antibot / marketplace HTML):
//     each has Cost set to the **measured** response size for that
//     endpoint, set via a one-shot live curl during list curation.
//     The Discoverer only falls through to these when every API
//     endpoint has failed.
//
// IMPORTANT: the Cost numbers + Parser choices for the TODO
// endpoints below are best-effort scaffolding. The follow-up
// agent task is to:
//
//	for each TODO endpoint:
//	  1. curl the URL with a realistic User-Agent;
//	  2. find the IP in the response body (json key? html attr?);
//	  3. for HTML: measure body size, set Cost to that byte count
//	     (rounded to nearest KB);
//	  4. add a hermetic test with a canned response.
//
// The Discoverer re-sorts by Cost at construction time so manual
// overrides to the values below still get correct priority order.
var DefaultEndpoints = []Endpoint{
	// ── API endpoints — CostMinimal, race in parallel ────────────
	{
		Name:    "qms",
		URL:     "https://www.qms.ru/api/asn_provider/ip",
		Family:  Any,
		Cost:    CostMinimal,
		Headers: map[string]string{"X-Api-Key": "c2852614b821db79e99218cce8d32b3d"},
		Parser:  JSONKey("ip"),
	},
	{
		// Live-verified: returns `{"ip":"..."}` (21 bytes) with the
		// same /api/asn_provider/ip shape as qms.
		Name:    "rt-speedtest",
		URL:     "https://speedtest.rt.ru/api/asn_provider/ip",
		Family:  Any,
		Cost:    CostMinimal,
		Headers: map[string]string{"X-Api-Key": "f85f12b942ab0a8818eb66d64b244ee5"},
		Parser:  JSONKey("ip"),
	},
	{
		Name:   "ipinfo",
		URL:    "https://ipinfo.io/json",
		Family: Any,
		Cost:   CostMinimal,
		// Documented: {"ip":"...","hostname":"...","city":"...",...}.
		Parser: JSONKey("ip"),
	},
	{
		// Live-verified: `{"ip":"...","success":true}` (37 bytes).
		Name:   "reg-speedtest",
		URL:    "https://speedtest.reg.ru/detect_ip_info",
		Family: Any,
		Cost:   CostMinimal,
		Parser: JSONKey("ip"),
	},
	// alfabank removed: /api/v2/geo-facade/geo/ip 307-redirects to
	// itself with `set-cookie: spid=...` for any request that doesn't
	// already carry the antibot cookie pair, producing an infinite
	// redirect loop on a stateless client. Even with cookie jar
	// wiring the upstream insists on a JS-set companion cookie that
	// curl / surf can't synthesise. Not viable as a stateless probe.
	{
		Name:   "yandex-v4",
		URL:    "https://ipv4-internet.yandex.net/api/v0/ip",
		Family: V4,
		Cost:   CostMinimal,
		Parser: JSONQuoted(),
	},
	{
		Name:   "yandex-v6",
		URL:    "https://ipv6-internet.yandex.net/api/v0/ip",
		Family: V6,
		Cost:   CostMinimal,
		Parser: JSONQuoted(),
	},
	{
		// Live-verified: JSONP-shaped body
		// `(none)({"ipAddress": "...", "xForwardedFor": "(none)"})`
		// — 65 bytes. JSONKey("ipAddress") matches inside the
		// JSONP wrapper just like a plain JSON object.
		Name:   "mail-ip",
		URL:    "https://ip.mail.ru/ip.html",
		Family: Any,
		Cost:   CostMinimal,
		Parser: JSONKey("ipAddress"),
	},

	// ── HTML landing pages — Cost = measured body size in bytes ──
	{
		// Live-verified at ~114 KB. The page embeds state JSON
		// containing two relevant keys: `"ip":"Нюрнберг"` (a CITY
		// name, leftover from a different schema branch) and
		// `"v4":"159.195.6.55"` (the actual IP, nested inside
		// `"ip":{"v4":...,"v6":null}`). We parse `"v4"` for the V4
		// race and split out a separate V6 entry below.
		Name:   "yandex-internet-v4",
		URL:    "https://yandex.ru/internet/",
		Family: V4,
		Cost:   114200,
		Parser: Regex(`"v4"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"`),
	},
	{
		// Same page; V6 race parses the `"v6":"..."` key from the
		// same state JSON. v6 is `null` on v4-only egress, so this
		// parser fails cleanly there.
		Name:   "yandex-internet-v6",
		URL:    "https://yandex.ru/internet/",
		Family: V6,
		Cost:   114200,
		Parser: Regex(`"v6"\s*:\s*"([0-9a-fA-F:]+)"`),
	},
	{
		// Live-verified at ~6.9 KB. The IP is in a small markup
		// fragment `<p>IP: 1.2.3.4</p>` — match the literal prefix
		// to avoid catching the unrelated `120.0.0.0` user-agent
		// version that also appears in the page.
		Name:   "mail-speedtest",
		URL:    "https://speedtest.mail.ru/",
		Family: Any,
		Cost:   6900,
		Parser: Regex(`IP:\s*((?:\d{1,3}\.){3}\d{1,3})`),
	},
	{
		// Live-verified: wildberries returns a small antibot-style
		// landing (~1.6 KB on foreign egress, larger inside RU) and
		// the requester IP sits in `data-req-ip="..."` on the root
		// <html> element. From foreign IPs the page comes back HTTP
		// 451 (Unavailable For Legal Reasons) so the discoverer
		// rejects it; from inside the RU segment it returns 200.
		// Cost measured on the antibot variant — full landing
		// inside RU is unmeasured from this environment.
		Name:   "wildberries",
		URL:    "https://www.wildberries.ru/",
		Family: Any,
		Cost:   1600,
		Parser: HTMLAttr("data-req-ip"),
	},
	{
		// Live-verified: litres is fronted by DDoS-Guard, which
		// injects a `__ddg9_=<client-ip>` Set-Cookie alongside
		// `__ddg8_`/`__ddg10_`/`__ddg1_` siblings. The IP comes
		// back in the HEADER, not the body — the Cookie parser
		// reads it from Set-Cookie without touching the body.
		// Body is still downloaded (557 KB landing, capped at
		// the Discoverer's 256 KB) because we don't have a
		// header-only optimisation yet; Cost is set to the
		// effective cap, not the full body. If we add a HEAD or
		// Range-request short-circuit later, drop Cost to ~500.
		Name:   "litres",
		URL:    "https://www.litres.ru/",
		Family: Any,
		Cost:   256000,
		Parser: Cookie("__ddg9_"),
	},
	{
		// Live-verified at ~1.77 MB. The IP appears in a JSON
		// island as `"remoteAddress":"..."` at byte ~255200 — just
		// inside the Discoverer's 256 KB response cap. Fragile: a
		// page reorganisation that pushes the island past 256 KB
		// will silently break this endpoint (parser_miss). Kept
		// because no cheaper alternative answers from inside RU
		// for this domain.
		Name:   "tbank",
		URL:    "https://www.tbank.ru",
		Family: Any,
		Cost:   1770000,
		Parser: JSONKey("remoteAddress"),
	},
	// avito removed: the landing page is ~1 MB and the requester
	// IP sits at byte offset ~1.04 MB in the body — well past the
	// Discoverer's 256 KB response cap. Bumping the cap just for
	// avito would let any other misconfigured endpoint stream
	// megabytes. Not worth the trade.
}
