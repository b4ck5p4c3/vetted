package vetted

// Parser tests. One positive + one or more negative cases per parser
// type, plus snapshots of the real response shapes observed during
// live verification of DefaultEndpoints - kept inline (not under
// testdata/) so the expected wire format is obvious to a reviewer.

import (
	"net/http"
	"strings"
	"testing"
)

func TestJSONKey_PositiveAndNegative(t *testing.T) {
	p := JSONKey("ip")

	got, err := p.Parse(nil, []byte(`{"ip":"203.0.113.7"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "203.0.113.7" {
		t.Errorf("got %q, want 203.0.113.7", got)
	}

	if _, err := p.Parse(nil, []byte(`{"address":"203.0.113.7"}`)); err == nil {
		t.Errorf("expected error when key absent, got nil")
	}

	// Unquoted value: JSONKey only matches `"k":"v"` (string value).
	// {"ip":1234567} is not a parser-fail by spec - the key has no
	// QUOTED value - so a miss is the correct outcome.
	if _, err := p.Parse(nil, []byte(`{"ip":1234567}`)); err == nil {
		t.Errorf("expected error when value not quoted, got nil")
	}
}

func TestJSONKey_WhitespaceAndJSONPWrapper(t *testing.T) {
	p := JSONKey("ipAddress")
	// Snapshot of `ip.mail.ru/ip.html` - JSONP wrapper around a
	// flat object. JSONKey ignores the wrapper because the regex
	// doesn't anchor to `{`.
	const mailIPBody = `(none)({"ipAddress": "159.195.6.55", "xForwardedFor": "(none)"})`
	got, err := p.Parse(nil, []byte(mailIPBody))
	if err != nil {
		t.Fatalf("mail-ip parse: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("mail-ip got %q, want 159.195.6.55", got)
	}
}

func TestJSONQuoted_PositiveAndNegative(t *testing.T) {
	p := JSONQuoted()

	// Snapshot of `ipv4-internet.yandex.net/api/v0/ip` - a single
	// quoted IP literal.
	got, err := p.Parse(nil, []byte(`"159.195.6.55"`))
	if err != nil {
		t.Fatalf("yandex v4 quoted: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("got %q, want 159.195.6.55", got)
	}

	if _, err := p.Parse(nil, []byte(`159.195.6.55`)); err == nil {
		t.Errorf("expected error when no quotes present, got nil")
	}
}

func TestHTMLAttr_PositiveAndNegative(t *testing.T) {
	p := HTMLAttr("data-req-ip")

	// Snapshot of the wildberries 451 antibot landing (truncated
	// to the relevant root-element fragment).
	const wbFragment = `<!DOCTYPE html><html lang="ru" data-theme="light" data-req-uuid="abc" data-req-ip="159.195.6.55" data-error-code="451">`
	got, err := p.Parse(nil, []byte(wbFragment))
	if err != nil {
		t.Fatalf("wildberries parse: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("got %q, want 159.195.6.55", got)
	}

	if _, err := p.Parse(nil, []byte(`<html lang="ru"></html>`)); err == nil {
		t.Errorf("expected error when attr absent, got nil")
	}
}

func TestRegex_CaptureGroupHandling(t *testing.T) {
	// Snapshot of speedtest.mail.ru - `<p>IP: 1.2.3.4</p>` markup,
	// alongside an unrelated `120.0.0.0` (user-agent version) that
	// the parser must NOT catch.
	const mailSpeedtestFragment = `<script>var ua="Chrome/120.0.0.0";</script><p>IP: 159.195.6.55</p>`
	p := Regex(`IP:\s*((?:\d{1,3}\.){3}\d{1,3})`)
	got, err := p.Parse(nil, []byte(mailSpeedtestFragment))
	if err != nil {
		t.Fatalf("mail-speedtest regex: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("got %q, want 159.195.6.55", got)
	}

	noMatch := Regex(`IP:\s*((?:\d{1,3}\.){3}\d{1,3})`)
	if _, err := noMatch.Parse(nil, []byte(`no such pattern here`)); err == nil {
		t.Errorf("expected error when regex misses, got nil")
	}
}

// TestYandexInternetState - snapshot of the v4/v6 keys lifted from
// yandex.ru/internet/'s embedded state JSON. Crucially the page
// ALSO contains `"ip":"<city name>"` from a different schema branch,
// so a naive JSONKey("ip") parser would catch the city. The agent-
// landed default uses `"v4":"..."` / `"v6":"..."` which is unambiguous.
func TestYandexInternetState(t *testing.T) {
	// Mirrors the body shape observed live.
	const stateSnippet = `{"experiments":{},"logoLang":"ru","ip":{"v4":"159.195.6.55","v6":null},"isp":{"asn":[197540]},"city":{"name":"Frankfurt","key":"ip":"Нюрнберг"}}`

	v4 := Regex(`"v4"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"`)
	got, err := v4.Parse(nil, []byte(stateSnippet))
	if err != nil {
		t.Fatalf("v4 parse: %v", err)
	}
	if got != "159.195.6.55" {
		t.Fatalf("v4 got %q, want 159.195.6.55", got)
	}

	v6 := Regex(`"v6"\s*:\s*"([0-9a-fA-F:]+)"`)
	if _, err := v6.Parse(nil, []byte(stateSnippet)); err == nil {
		t.Errorf("v6 parse should miss when value is null, got match")
	}

	const stateWithV6 = `{"ip":{"v4":"203.0.113.7","v6":"2001:db8::1"}}`
	got6, err := v6.Parse(nil, []byte(stateWithV6))
	if err != nil {
		t.Fatalf("v6 parse with value: %v", err)
	}
	if got6 != "2001:db8::1" {
		t.Errorf("v6 got %q, want 2001:db8::1", got6)
	}
}

// TestTbankStateJSON - snapshot of the `remoteAddress` JSON island
// from www.tbank.ru's landing page. Pinned because that island sits
// at byte ~255 KB in the live body, right against the Discoverer's
// 256 KB cap; the parser shape itself must keep working even if the
// surrounding markup rearranges.
func TestTbankStateJSON(t *testing.T) {
	const tbankFragment = `tracking.state = JSON.parse('{"appName":"pwaplatform","remoteAddress":"159.195.6.55","userAgent":{"browser":{"name":"chrome"}}}');`
	p := JSONKey("remoteAddress")
	got, err := p.Parse(nil, []byte(tbankFragment))
	if err != nil {
		t.Fatalf("tbank parse: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("got %q, want 159.195.6.55", got)
	}
}

// TestParserFuncAdapter verifies the ParserFunc adapter implements
// the Parser interface so callers can pass a closure where Parser
// is expected.
func TestParserFuncAdapter(t *testing.T) {
	var p Parser = ParserFunc(func(_ http.Header, b []byte) (string, error) {
		return strings.TrimSpace(string(b)), nil
	})
	got, err := p.Parse(nil, []byte("  203.0.113.7  "))
	if err != nil {
		t.Fatal(err)
	}
	if got != "203.0.113.7" {
		t.Errorf("got %q, want 203.0.113.7", got)
	}
}

// TestLamodaVPNErrorShape - snapshot of the 403 VPN-detected body
// shared by /recommendations/section, /information/get and
// /cms/topmenu_flexible. The IP rides as `data.ip`; JSONKey("ip")
// matches the first "ip":"..." token in the JSON regardless of
// nesting depth. Pinned because all three endpoints in
// DefaultEndpoints depend on this exact shape.
func TestLamodaVPNErrorShape(t *testing.T) {
	const body = `{"code":10403,"message":"Попробуйте отключить VPN или выбрать другую сеть Wi-Fi","title":"VPN мешает загрузке","data":{"ip":"159.195.6.55"}}`
	p := JSONKey("ip")
	got, err := p.Parse(nil, []byte(body))
	if err != nil {
		t.Fatalf("lamoda parse: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("got %q, want 159.195.6.55", got)
	}
}

// TestIviStateShape - snapshot of the single `"ip":"..."` token
// from ivi.tv's embedded state JSON. Live body is 748 KB with the
// token at byte ~266 K; the parser shape itself is plain JSONKey
// and the byte-offset constraint lives on Endpoint.MaxBytes. Pin
// the parser shape here because a future ivi redesign that moves
// the IP into a nested key (`"client":{"ip":"..."}`) still parses
// (regex matches anywhere) but a redesign that renames the key
// entirely needs a re-verify.
func TestIviStateShape(t *testing.T) {
	const fragment = `{"abTest":{"state":{"ip":"159.195.6.55","exp":["A","B"]}}}`
	p := JSONKey("ip")
	got, err := p.Parse(nil, []byte(fragment))
	if err != nil {
		t.Fatalf("ivi parse: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("got %q, want 159.195.6.55", got)
	}
}

// TestCookieParser_LitresShape - snapshot of the DDoS-Guard cookie
// pair that fronts litres.ru. The IP rides in `__ddg9_=<ip>`
// alongside several sibling cookies (`__ddg8_`, `__ddg10_`,
// `__ddg1_`, etc.); the parser must pick only the named one and
// must not be confused by attribute lists separated with `;`.
func TestCookieParser_LitresShape(t *testing.T) {
	p := Cookie("__ddg9_")
	h := http.Header{}
	h.Add("Set-Cookie", "__ddg8_=REX2uQXVnvgD7gQv; Domain=.litres.ru; Path=/; Expires=Tue, 19-May-2026 22:18:36 GMT")
	h.Add("Set-Cookie", "__ddg10_=1779227916; Domain=.litres.ru; Path=/")
	h.Add("Set-Cookie", "__ddg9_=159.195.6.55; Domain=.litres.ru; Path=/; Expires=Tue, 19-May-2026 22:18:36 GMT")
	h.Add("Set-Cookie", "supersid=da3b535a-d16f; Path=/; Secure")

	got, err := p.Parse(h, nil)
	if err != nil {
		t.Fatalf("Cookie parse: %v", err)
	}
	if got != "159.195.6.55" {
		t.Errorf("got %q, want 159.195.6.55", got)
	}

	// Negative: named cookie absent.
	h2 := http.Header{}
	h2.Add("Set-Cookie", "session=abc; Path=/")
	if _, err := p.Parse(h2, nil); err == nil {
		t.Errorf("expected error when cookie absent, got nil")
	}
}
