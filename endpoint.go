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

// Endpoint describes one IP-echo service. Name is the short
// identifier used in logs and span tags (no spaces). Parser
// extracts the IP candidate from the response; the Discoverer
// then validates with net.ParseIP and rejects family-mismatched
// candidates.
type Endpoint struct {
	Name    string
	URL     string
	Family  Family
	Cost    Cost
	Headers map[string]string
	Parser  Parser

	// AcceptStatus, when non-empty, lists HTTP status codes that
	// are treated as "successful enough" to attempt body parse.
	// Empty (default) means 200-299. Use to accommodate services
	// that echo the requester IP in an antibot 403 / VPN-blocker
	// 403 — 2gis.ru and lamoda's recommendations API both behave
	// this way: a 403 body carries the IP as the entire reason for
	// the rejection, and that body shape is more stable than the
	// "happy path" 200 page (which is huge and may not embed the
	// IP at all from foreign egress).
	AcceptStatus []int

	// Method overrides the HTTP verb. Empty defaults to "GET".
	// Must be one of GET / POST / PUT / PATCH / DELETE / HEAD /
	// OPTIONS — Validate rejects anything else so a typo doesn't
	// silently fall back to GET. Used for JSON-POST APIs like
	// lamoda's that return 400 to a plain GET but echo the
	// requester IP for an empty `{}` POST body.
	Method string

	// Body is the request body. Nil → no body (the default).
	// Used alongside Method == "POST" / "PUT" / "PATCH". The
	// Discoverer reads from a fresh bytes.Reader on every attempt
	// so this slice is safe to share between cycles; treat it as
	// immutable from the caller side once the Endpoint is handed
	// to New().
	Body []byte

	// MaxBytes overrides the package-default 256 KB response cap
	// for this endpoint specifically. Zero (the default) means
	// "use the package default". Non-zero values may be larger
	// OR smaller than the package default — the response is
	// capped at MaxBytes verbatim, never widened back to the
	// package default. Used for endpoints whose IP echo sits past
	// 256 KB in a multi-hundred-KB landing page (ivi.tv at byte
	// ~266 KB, etc.); pay the bandwidth so the parser actually
	// sees the IP. Set Cost to the same value as MaxBytes so the
	// tier ordering reflects the bytes you will actually pull.
	MaxBytes int
}

// method returns the HTTP verb to use for this endpoint, defaulting
// to GET when Method is empty. Centralised so attempt() doesn't
// repeat the default-string check inline.
func (e Endpoint) method() string {
	if e.Method == "" {
		return "GET"
	}
	return e.Method
}

// readCap returns the byte cap to apply to this endpoint's response
// body. MaxBytes wins when set; otherwise the package default
// applies. Centralised so the cap-selection rule lives next to the
// field documentation.
func (e Endpoint) readCap() int64 {
	if e.MaxBytes > 0 {
		return int64(e.MaxBytes)
	}
	return int64(maxResponseBytes)
}

// acceptStatus returns true if the response code is in this
// endpoint's accept set. AcceptStatus nil → default 200-299 range.
func (e Endpoint) acceptStatus(code int) bool {
	if len(e.AcceptStatus) == 0 {
		return code >= 200 && code < 300
	}
	for _, c := range e.AcceptStatus {
		if c == code {
			return true
		}
	}
	return false
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
	if e.Method != "" {
		if _, ok := knownMethods[e.Method]; !ok {
			return fmt.Errorf("vetted: endpoint %q has invalid Method %q", e.Name, e.Method)
		}
	}
	if e.MaxBytes < 0 {
		return fmt.Errorf("vetted: endpoint %q has negative MaxBytes %d", e.Name, e.MaxBytes)
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
	{
		// Live-verified: 548 B body with `"ip":"..."` plus
		// proxy / geo metadata. Plain 200 / JSON shape.
		Name:   "start-proxycheck",
		URL:    "https://api.start.ru/account/proxycheck?apikey=a20b12b279f744f2b3c7b5c5400c4eb5",
		Family: Any,
		Cost:   CostMinimal,
		Parser: JSONKey("ip"),
	},
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
		// Earlier removal commentary in this file documented an
		// "infinite redirect loop" — that was the
		// `?detect_ip=true` variant, which 307s into a different
		// JS-cookie flow. The bare path (no query) is a clean
		// one-hop replay. AcceptStatus opts the 404 past the 2xx
		// gate; the matching Accept header keeps ServicePipe on
		// the HTML-replay branch rather than serving the JSON
		// "406 Not Acceptable" path.
		Name:   "alfabank",
		URL:    "https://alfabank.ru/api/v2/geo-facade/geo/ip",
		Family: Any,
		Cost:   CostMinimal,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
		AcceptStatus: []int{200, 404},
		Parser:       Regex(`IP\s+((?:\d{1,3}\.){3}\d{1,3})`),
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
		// `__ddg8_`/`__ddg10_`/`__ddg1_` siblings. The IP rides in
		// the HEADER, not the body — so we send HEAD instead of GET
		// and DDoS-Guard still echoes the cookie in the response
		// headers (live-verified: identical __ddg9_ value on HEAD
		// vs GET). Saves ~256 KB per cycle that this endpoint fires,
		// which matters for the mobile-RU target where the cheap
		// API tier often fails and litres pulls through.
		//
		// Cost set to CostSmall — the actual response is just
		// headers (~600 B from this egress), but bumping above
		// CostMinimal keeps litres out of the parallel API race
		// where the cheap JSON endpoints belong. Litres is still
		// effectively a fallback because its measured latency
		// (~200ms + DDoS-Guard overhead) loses cleanly against
		// the sub-100ms JSON endpoints.
		Name:   "litres",
		URL:    "https://www.litres.ru/",
		Family: Any,
		Cost:   CostSmall,
		Method: "HEAD",
		Parser: Cookie("__ddg9_"),
	},
	{
		// Live-verified: lamoda's recommendations API returns
		// HTTP 403 with body
		// `{"code":10403,"message":"...","data":{"ip":"..."}}`
		// (194 B) on requests from VPN / non-RU IPs — the IP is
		// echoed back as part of the "VPN detected" payload.
		// Requires AcceptStatus to opt past the 2xx gate.
		//
		// EGRESS-DIRECTION CAVEAT (applies to every lamoda-* probe
		// in this list). The 403-with-IP payload only fires when
		// lamoda's antibot classifies the caller's egress IP as
		// VPN / suspect / foreign. From a "trusted" domestic RU IP
		// the same URL responds HTTP 307 with a cookie-set
		// redirect that loops indefinitely — never reaches 200
		// nor 403, and the response body is a literal "blank\n"
		// (5 B) with no IP payload. Net effect: lamoda-* probes
		// SUCCEED for callers running this library behind a VPN
		// (or on a non-RU host probing into RU) and SILENTLY
		// FAIL for callers running on a domestic RU host. They
		// stay in the default set because the failure is graceful
		// — the discoverer just records a non-matching FailReason
		// and falls through to the next endpoint — but operators
		// should not expect lamoda hits in their span tags from
		// in-country deployments.
		Name:         "lamoda-vpn-error",
		URL:          "https://www.lamoda.ru/api/v1/recommendations/section",
		Family:       Any,
		Cost:         194,
		Parser:       JSONKey("ip"),
		AcceptStatus: []int{200, 403},
	},
	{
		// Live-verified: 2gis returns a 403 antibot landing on
		// every stateless request (~1.4 KB) with the requester
		// IP echoed as `<p id="REQUEST-IP">IP: <ip></p>`. The
		// 200 happy path from inside RU likely has a different
		// shape and the parser misses cleanly — accepting both
		// codes is safe because parse failure is a soft error.
		Name:         "2gis-antibot",
		URL:          "https://2gis.ru/",
		Family:       Any,
		Cost:         1411,
		Parser:       Regex(`REQUEST-IP[^<]*IP:\s*((?:\d{1,3}\.){3}\d{1,3})`),
		AcceptStatus: []int{200, 403},
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
	{
		// Live-verified from both foreign and domestic-RU egress.
		// Domestic RU: HTTP 200, 985 KB landing, IP embedded three
		// times as `"ip":"<addr>"` near byte offset ~958 K — needs
		// MaxBytes ~1_000_000 to reach. Foreign egress: HTTP 403,
		// 27 KB antibot interstitial ("Доступ ограничен: проблема
		// с IP"), no IP echo anywhere → parser_miss, the
		// discoverer just falls through to the next endpoint. Range
		// header (`bytes=1000000-1100000`) is ignored in both
		// directions (full body returned, not 206), so partial
		// fetch is not possible.
		//
		// Cost is the full 1_000_000 B on purpose: callers cap
		// eligibility with WithMaxCost. Default (no cap) lets
		// avito race; WithMaxCost(CostMedium) or any value <
		// 1_000_000 silently drops it. That is the honest
		// bandwidth trade-off — the library does not hide the
		// price, the caller chooses whether to pay it.
		Name:     "avito",
		URL:      "https://www.avito.ru/",
		Family:   Any,
		Cost:     1_000_000,
		Parser:   JSONKey("ip"),
		MaxBytes: 1_000_000,
	},
	{
		// Live-verified: 748801 B body with a single
		// `"ip":"159.195.6.55"` token at byte offset 266202. JSONKey
		// matches because the body contains exactly one "ip" key
		// (verified by grep on the full body). MaxBytes=300_000
		// gives a ~33 KB margin above the IP position so a page
		// reshuffle doesn't immediately break it; Cost matches
		// MaxBytes because that is the byte volume we will actually
		// pull when this endpoint runs.
		Name:     "ivi",
		URL:      "https://www.ivi.tv/",
		Family:   Any,
		Cost:     300_000,
		Parser:   JSONKey("ip"),
		MaxBytes: 300_000,
	},
	{
		// Live-verified: POST {} to
		// /api/v1/information/get returns 403 with the same VPN-
		// detected shape lamoda-vpn-error uses
		// (`{"code":10403,"data":{"ip":"<ip>"},"message":"...","title":"..."}`,
		// 194 B). Plain GET 400s with "The method does not exists" —
		// requires the new Method + Body wiring. AcceptStatus
		// retained to opt the 403 past the 2xx gate.
		//
		// Same EGRESS-DIRECTION CAVEAT as lamoda-vpn-error above:
		// the IP-bearing 403 only fires from VPN / foreign egress;
		// from a domestic RU IP the same URL responds HTTP 307
		// "blank\n" indefinitely. See that endpoint's comment for
		// the full explanation.
		Name:         "lamoda-information-get",
		URL:          "https://www.lamoda.ru/api/v1/information/get",
		Family:       Any,
		Cost:         CostMinimal,
		Method:       "POST",
		Body:         []byte(`{}`),
		Headers:      map[string]string{"Content-Type": "application/json"},
		Parser:       JSONKey("ip"),
		AcceptStatus: []int{200, 403},
	},
	{
		// Live-verified: same shape and same body as
		// lamoda-information-get above — POST {} → 403 with
		// `data.ip` echoed. Kept as a sibling so a single API path
		// flapping does not knock out the entire lamoda probe set.
		// Same EGRESS-DIRECTION CAVEAT applies; see lamoda-vpn-error.
		Name:         "lamoda-topmenu-flexible",
		URL:          "https://www.lamoda.ru/api/v1/cms/topmenu_flexible",
		Family:       Any,
		Cost:         CostMinimal,
		Method:       "POST",
		Body:         []byte(`{}`),
		Headers:      map[string]string{"Content-Type": "application/json"},
		Parser:       JSONKey("ip"),
		AcceptStatus: []int{200, 403},
	},
}
