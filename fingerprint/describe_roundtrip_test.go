package fingerprint

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// TestDescribeRoundTripsEveryPreset: describing a preset and loading the result
// back has to give a preset that behaves identically, because that is the
// documented way to start a custom preset from a built-in one (#125).
//
// Behaviour is compared through what the transport reads: every no-argument
// getter on Preset, the per-dest HTTP/2 priority lookup, and the TLS identity
// fields the spec builders use. Comparing struct fields directly would be
// wrong, since describe deliberately writes resolved defaults out explicitly
// where the original leaves them nil.
//
// This found two losses when it was written: image_accept was never exported,
// so every Chrome 155 preset came back with the 154 image Accept, and the
// HTTP/3 profile was only exported when HTTP/3 was on by default, so
// safari-17-ios came back with Chrome's QUIC settings.
func TestDescribeRoundTripsEveryPreset(t *testing.T) {
	var names []string
	for n := range presets {
		names = append(names, n)
	}
	sort.Strings(names)

	dests := []string{"document", "iframe", "image", "script", "style", "font",
		"empty", "manifest", "audio", "video", "worker", "not-a-dest"}

	for _, name := range names {
		desc, err := Describe(name)
		if err != nil {
			t.Errorf("%s: describe: %v", name, err)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(desc), &m); err != nil {
			t.Fatalf("%s: describe produced invalid JSON: %v", name, err)
		}
		m["preset"].(map[string]any)["name"] = name + "-roundtrip"
		b, _ := json.Marshal(m)
		clone, err := LoadAndBuildPresetFromJSON(b)
		if err != nil {
			t.Errorf("%s: described preset does not load back: %v", name, err)
			continue
		}
		orig := Get(name)

		o, c := reflect.ValueOf(orig), reflect.ValueOf(clone)
		for i := 0; i < o.Type().NumMethod(); i++ {
			mt := o.Type().Method(i)
			if mt.Type.NumIn() != 1 || mt.Type.NumOut() == 0 {
				continue
			}
			ro, rc := o.Method(i).Call(nil), c.Method(i).Call(nil)
			for k := range ro {
				if !reflect.DeepEqual(ro[k].Interface(), rc[k].Interface()) {
					t.Errorf("%s: %s() = %v, but %v after a describe round trip",
						name, mt.Name, ro[k].Interface(), rc[k].Interface())
					break
				}
			}
		}
		for _, d := range dests {
			w1, e1, h1, ok1 := orig.H2PriorityFor(d)
			w2, e2, h2, ok2 := clone.H2PriorityFor(d)
			if w1 != w2 || e1 != e2 || h1 != h2 || ok1 != ok2 {
				t.Errorf("%s: H2PriorityFor(%q) changed in the round trip", name, d)
			}
		}
		for field, pair := range map[string][2]any{
			"ClientHelloID":           {orig.ClientHelloID, clone.ClientHelloID},
			"PSKClientHelloID":        {orig.PSKClientHelloID, clone.PSKClientHelloID},
			"QUICClientHelloID":       {orig.QUICClientHelloID, clone.QUICClientHelloID},
			"QUICPSKClientHelloID":    {orig.QUICPSKClientHelloID, clone.QUICPSKClientHelloID},
			"SignatureAlgorithms":     {orig.SignatureAlgorithms, clone.SignatureAlgorithms},
			"QUICSignatureAlgorithms": {orig.QUICSignatureAlgorithms, clone.QUICSignatureAlgorithms},
			"TrustAnchors":            {orig.TrustAnchors, clone.TrustAnchors},
			"QUICTrustAnchorShuffle":  {orig.QUICTrustAnchorShuffle, clone.QUICTrustAnchorShuffle},
			"JA3":                     {orig.JA3, clone.JA3},
			"UserAgent":               {orig.UserAgent, clone.UserAgent},
			"HeaderOrder":             {orig.HeaderOrder, clone.HeaderOrder},
			"SupportHTTP3":            {orig.SupportHTTP3, clone.SupportHTTP3},
		} {
			if !reflect.DeepEqual(pair[0], pair[1]) {
				t.Errorf("%s: %s changed in the round trip", name, field)
			}
		}
	}
}
