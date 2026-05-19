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
		Name:    "rt-speedtest",
		URL:     "https://speedtest.rt.ru/api/asn_provider/ip",
		Family:  Any,
		Cost:    CostMinimal,
		Headers: map[string]string{"X-Api-Key": "f85f12b942ab0a8818eb66d64b244ee5"},
		// Same /api/asn_provider/ip pattern as qms; almost certainly
		// the same {"ip":"..."} shape. TODO(agent): live-verify.
		Parser: JSONKey("ip"),
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
		// TODO(agent): live-check. URL says detect_ip_info — likely
		// {"ip":"...","country":"...",...}. Verify shape.
		Name:   "reg-speedtest",
		URL:    "https://speedtest.reg.ru/detect_ip_info",
		Family: Any,
		Cost:   CostMinimal,
		Parser: JSONKey("ip"),
	},
	{
		// TODO(agent): live-check. Alfabank geo facade probably
		// returns {"ip":"...","country":"...","city":"..."} or
		// wrapped {"data":{"ip":"..."}}. Confirm key path.
		Name:   "alfabank",
		URL:    "https://alfabank.ru/api/v2/geo-facade/geo/ip?detect_ip=true",
		Family: Any,
		Cost:   CostMinimal,
		Parser: JSONKey("ip"),
	},
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
		// TODO(agent): live-check. ip.mail.ru/ip.html is HTML but
		// typically tiny — just a page showing the IP. Find the
		// markup pattern (likely `<p>1.2.3.4</p>` or
		// `<span ...>1.2.3.4</span>`). Measure body size; if it
		// really is <500 bytes, keep at CostMinimal, otherwise
		// bump to the measured value.
		Name:   "mail-ip",
		URL:    "https://ip.mail.ru/ip.html",
		Family: Any,
		Cost:   CostMinimal,
		// Regex placeholder; the actual pattern depends on markup.
		Parser: Regex(`\b((?:\d{1,3}\.){3}\d{1,3})\b`),
	},

	// ── HTML landing pages — Cost = measured body size in bytes ──
	{
		// TODO(agent): live-check. yandex.ru/internet/ embeds JSON
		// state in HTML; earlier observation showed `"ip":"..."`
		// somewhere in the body (and also `"ip":"<city name>"` —
		// generic JSONKey("ip") will pick the first which may not
		// be the right one). Verify the order and write a tighter
		// parser if needed. Measure body size for Cost.
		Name:   "yandex-internet",
		URL:    "https://yandex.ru/internet/",
		Family: Any,
		Cost:   CostMedium, // TODO: replace with measured byte count
		Parser: Regex(`"ip"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"`),
	},
	{
		// TODO(agent): live-check + measure. speedtest.mail.ru/ is
		// a landing page; find the IP in the markup and write the
		// matching parser.
		Name:   "mail-speedtest",
		URL:    "https://speedtest.mail.ru/",
		Family: Any,
		Cost:   CostMedium, // TODO: measured byte count
		Parser: Regex(`"ip"\s*:\s*"([^"]+)"`),
	},
	{
		Name:   "wildberries",
		URL:    "https://www.wildberries.ru/",
		Family: Any,
		Cost:   CostHigh, // ~3 KB antibot landing in practice
		Parser: HTMLAttr("data-req-ip"),
	},
	{
		// TODO(agent): live-check + measure. tbank.ru is a landing
		// page; need to find where the IP appears (Cloudfront echo,
		// embedded JSON, etc.).
		Name:   "tbank",
		URL:    "https://www.tbank.ru",
		Family: Any,
		Cost:   CostHigh, // TODO: measured byte count
		Parser: Regex(`"ip"\s*:\s*"([^"]+)"`),
	},
	{
		// TODO(agent): live-check + measure. avito.ru landing
		// historically embeds the requester IP in a JSON island in
		// the HTML; confirm shape.
		Name:   "avito",
		URL:    "https://www.avito.ru/",
		Family: Any,
		Cost:   CostHigh, // TODO: measured byte count
		Parser: Regex(`"ip"\s*:\s*"([^"]+)"`),
	},
}
