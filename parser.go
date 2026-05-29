package vetted

import (
	"fmt"
	"net/http"
	"regexp"
)

// Parser extracts an IP candidate string from an endpoint's response.
// Implementations don't validate the IP - the Discoverer does that
// via net.ParseIP after the parser returns. Keep parsers pure: no
// IO, no globals, no parse-time allocations past what the regex/JSON
// walk inherently needs.
//
// Both headers and body are passed because some endpoints
// (DDoS-Guard-fronted sites like litres.ru) return the requester's
// IP in a Set-Cookie header rather than in the body. Parsers that
// only need the body ignore the headers argument; the function-style
// adapters below have body-only convenience wrappers.
type Parser interface {
	Parse(headers http.Header, body []byte) (string, error)
}

// ParserFunc adapts a plain function to the Parser interface.
type ParserFunc func(headers http.Header, body []byte) (string, error)

func (f ParserFunc) Parse(h http.Header, b []byte) (string, error) { return f(h, b) }

// bodyOnly wraps a body-only parse function as a Parser. Used by the
// stock body parsers below so their bodies stay readable.
func bodyOnly(f func([]byte) (string, error)) Parser {
	return ParserFunc(func(_ http.Header, b []byte) (string, error) { return f(b) })
}

// JSONKey returns a Parser that extracts the string value of a
// top-level "key": "..." pair from a JSON object body. Implemented
// as a regex because the JSON shapes we care about are flat and
// regex is dramatically cheaper than json.Unmarshal on a 50 KB
// body. The regex tolerates whitespace and works on nested objects
// as long as the named key carries an IP-shaped string somewhere.
//
// For ambiguous "ip" keys nested several levels deep where the
// regex would false-match, write a custom ParserFunc that does
// proper json.Unmarshal.
func JSONKey(key string) Parser {
	// Quote the key so a special-character key still works; we
	// don't have any with special characters but it's free defence.
	q := regexp.QuoteMeta(key)
	re := regexp.MustCompile(`"` + q + `"\s*:\s*"([^"]+)"`)
	return bodyOnly(func(body []byte) (string, error) {
		m := re.FindSubmatch(body)
		if len(m) < 2 {
			return "", fmt.Errorf("json key %q not found", key)
		}
		return string(m[1]), nil
	})
}

// JSONQuoted returns a Parser that captures the contents of the
// first pair of double quotes in the body. Use for endpoints whose
// entire response is a JSON-quoted IP, like
// `ipv4-internet.yandex.net/api/v0/ip` -> `"159.195.6.55"`.
func JSONQuoted() Parser {
	re := regexp.MustCompile(`"([^"]+)"`)
	return bodyOnly(func(body []byte) (string, error) {
		m := re.FindSubmatch(body)
		if len(m) < 2 {
			return "", fmt.Errorf("no quoted token found")
		}
		return string(m[1]), nil
	})
}

// HTMLAttr returns a Parser that extracts the first value of an
// HTML attribute, e.g. HTMLAttr("data-req-ip") matches
// `data-req-ip="159.195.6.55"` anywhere in the body. Useful for
// landing pages that echo the requester IP in a data-attribute on
// the root <html>.
func HTMLAttr(attr string) Parser {
	q := regexp.QuoteMeta(attr)
	re := regexp.MustCompile(q + `="([^"]+)"`)
	return bodyOnly(func(body []byte) (string, error) {
		m := re.FindSubmatch(body)
		if len(m) < 2 {
			return "", fmt.Errorf("html attr %q not found", attr)
		}
		return string(m[1]), nil
	})
}

// Regex returns a Parser backed by an arbitrary regex whose first
// capture group is the IP candidate. Panics at construction time
// if the pattern doesn't compile.
func Regex(pattern string) Parser {
	re := regexp.MustCompile(pattern)
	return bodyOnly(func(body []byte) (string, error) {
		m := re.FindSubmatch(body)
		if len(m) < 2 {
			return "", fmt.Errorf("regex %q did not match", pattern)
		}
		return string(m[1]), nil
	})
}

// Cookie returns a Parser that extracts the value of a Set-Cookie
// header whose name matches `name`. Use for endpoints whose
// upstream (typically a DDoS-Guard or similar CDN front) echoes
// the requester's IP into a cookie value - litres.ru with its
// `__ddg9_=<client-ip>` cookie is the canonical example.
//
// Multiple Set-Cookie headers are scanned in order; the first
// matching name wins. The cookie value is returned verbatim
// (no URL-decode) - DDoS-Guard's IP cookies are plain ASCII.
func Cookie(name string) Parser {
	return ParserFunc(func(h http.Header, _ []byte) (string, error) {
		// http.Header round-trips Set-Cookie under either canonical
		// "Set-Cookie" or, with some servers, plain casing. Values()
		// handles both.
		for _, raw := range h.Values("Set-Cookie") {
			// Parse manually rather than constructing an
			// http.Response just for ReadCookies - the format is
			// simple enough: name=value[; attr...].
			seg := raw
			if i := indexByte(seg, ';'); i >= 0 {
				seg = seg[:i]
			}
			eq := indexByte(seg, '=')
			if eq <= 0 {
				continue
			}
			if seg[:eq] != name {
				continue
			}
			return seg[eq+1:], nil
		}
		return "", fmt.Errorf("cookie %q not found", name)
	})
}

// indexByte is strings.IndexByte spelled inline to keep parser.go
// free of a strings import for one call site.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
