package vetted

import (
	"fmt"
	"regexp"
)

// Parser extracts an IP candidate string from an endpoint's
// response body. Implementations don't validate the IP — the
// Discoverer does that via net.ParseIP after the parser returns.
// Keep parsers pure: no IO, no globals, no parse-time allocations
// past what the regex/JSON walk inherently needs.
type Parser interface {
	Parse(body []byte) (string, error)
}

// ParserFunc adapts a plain function to the Parser interface.
type ParserFunc func(body []byte) (string, error)

func (f ParserFunc) Parse(body []byte) (string, error) { return f(body) }

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
	return ParserFunc(func(body []byte) (string, error) {
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
// `ipv4-internet.yandex.net/api/v0/ip` → `"159.195.6.55"`.
func JSONQuoted() Parser {
	re := regexp.MustCompile(`"([^"]+)"`)
	return ParserFunc(func(body []byte) (string, error) {
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
	return ParserFunc(func(body []byte) (string, error) {
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
	return ParserFunc(func(body []byte) (string, error) {
		m := re.FindSubmatch(body)
		if len(m) < 2 {
			return "", fmt.Errorf("regex %q did not match", pattern)
		}
		return string(m[1]), nil
	})
}
