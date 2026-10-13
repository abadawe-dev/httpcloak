package transport

import (
	"fmt"
	"reflect"
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestCanonicalHeaderName checks the memoised path against
// http.CanonicalHeaderKey for every byte value in every position class the
// quick check distinguishes: alone, after a letter, before a letter, after a
// hyphen, and inside an otherwise canonical name.
func TestCanonicalHeaderName(t *testing.T) {
	for c := range 256 {
		b := byte(c)
		for _, name := range []string{
			string([]byte{b}),
			"a" + string([]byte{b}),
			string([]byte{b}) + "a",
			"x-" + string([]byte{b}) + "b",
			"Content-" + string([]byte{b}) + "ype",
		} {
			if got, want := canonicalHeaderName(name), http.CanonicalHeaderKey(name); got != want {
				t.Errorf("canonicalHeaderName(%q) = %q, want %q", name, got, want)
			}
		}
	}

	for _, name := range []string{
		"",
		"accept",
		"Accept",
		"content-type",
		"Content-Type",
		"x-requested-with",
		"sec-ch-ua-platform",
		"ACCEPT-ENCODING",
		"aCCePt",
		"x--double",
		"-leading",
		"trailing-",
		"7-digit-start",
		"bad key",
		"bad:key",
		"bäd-key",
		"Bäd-Key",
		"mixedCase withSpace",
	} {
		if got, want := canonicalHeaderName(name), http.CanonicalHeaderKey(name); got != want {
			t.Errorf("canonicalHeaderName(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestMergeCallerHeaders checks the direct-assignment merge against the
// documented fold: for each caller name the first value replaces whatever the
// preset pipeline produced and the rest append, under the canonical key.
func TestMergeCallerHeaders(t *testing.T) {
	base := http.Header{
		"User-Agent":     {"preset-agent"},
		"Accept":         {"text/html"},
		"Sec-Fetch-Mode": {"navigate"},
	}
	cases := []struct {
		name    string
		headers map[string][]string
	}{
		{name: "nil"},
		{name: "empty", headers: map[string][]string{}},
		{name: "lowercase override and new", headers: map[string][]string{
			"accept":           {"application/json"},
			"authorization":    {"Bearer t"},
			"x-requested-with": {"XMLHttpRequest"},
		}},
		{name: "multi-value", headers: map[string][]string{
			"cookie": {"a=1", "b=2", "c=3"},
		}},
		{name: "empty value slice leaves the entry alone", headers: map[string][]string{
			"accept": {},
			"x-new":  {},
		}},
		{name: "already canonical", headers: map[string][]string{
			"Content-Type": {"application/json"},
			"User-Agent":   {"caller-agent"},
		}},
		{name: "weird casing", headers: map[string][]string{
			"x-WEIRD-key": {"v"},
			"aCCePt":      {"*/*"},
		}},
		{name: "invalid field byte stays raw", headers: map[string][]string{
			"bad key": {"v"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := &http.Request{Header: base.Clone()}
			mergeCallerHeaders(got, &Request{Headers: c.headers})

			want := base.Clone()
			for key, values := range c.headers {
				for i, value := range values {
					if i == 0 {
						want.Set(key, value)
					} else {
						want.Add(key, value)
					}
				}
			}
			if !reflect.DeepEqual(got.Header, want) {
				t.Errorf("mergeCallerHeaders(%v) header =\n%v\nwant\n%v", c.headers, got.Header, want)
			}
		})
	}
}

func TestMergeCallerHeadersExactHeadersNoOp(t *testing.T) {
	httpReq := &http.Request{Header: http.Header{"User-Agent": {"preset-agent"}}}
	want := httpReq.Header.Clone()
	mergeCallerHeaders(httpReq, &Request{
		Headers:      map[string][]string{"accept": {"application/json"}},
		ExactHeaders: []fingerprint.HeaderPair{{Key: "user-agent", Value: "exact"}},
	})
	if !reflect.DeepEqual(httpReq.Header, want) {
		t.Errorf("mergeCallerHeaders under ExactHeaders mutated the header: got %v, want %v", httpReq.Header, want)
	}
}

// The merged entries are carved out of one shared backing array and must not
// alias the caller's slices; each must keep the same isolation that the
// per-value Set and Add calls gave.
func TestMergeCallerHeadersIsolation(t *testing.T) {
	headers := map[string][]string{
		"cookie":       {"a=1", "b=2"},
		"accept":       {"application/json"},
		"x-first":      {"one"},
		"content-type": {"text/plain"},
	}
	httpReq := &http.Request{Header: http.Header{}}
	mergeCallerHeaders(httpReq, &Request{Headers: headers})

	before := map[string][]string{}
	for k, v := range httpReq.Header {
		before[k] = append([]string(nil), v...)
	}

	// Appending through one entry must not disturb its neighbors.
	httpReq.Header.Add("Cookie", "c=3")
	for _, k := range []string{"Accept", "X-First", "Content-Type"} {
		if !reflect.DeepEqual(httpReq.Header[k], before[k]) {
			t.Errorf("after Add to Cookie, header[%q] = %v, want %v", k, httpReq.Header[k], before[k])
		}
	}

	// Writing an element must not reach back into the caller's map.
	httpReq.Header["Accept"][0] = "mutated"
	if headers["accept"][0] != "application/json" {
		t.Errorf(`headers["accept"][0] = %q, want "application/json"`, headers["accept"][0])
	}
}

// A large caller map must not grow the bounded name cache without limit.
func TestCanonicalHeaderNameCacheBounded(t *testing.T) {
	for i := range canonicalHeaderNameCacheMax * 2 {
		canonicalHeaderName(fmt.Sprintf("x-bound-probe-%d", i))
	}
	// Concurrent stores can each overshoot the soft cap by one; anything in
	// that neighborhood is fine, a multiple of it is a leak.
	if n := canonicalHeaderNameCacheSize.Load(); n > canonicalHeaderNameCacheMax+8 {
		t.Errorf("canonicalHeaderNameCacheSize = %d, want <= %d", n, canonicalHeaderNameCacheMax+8)
	}
}
