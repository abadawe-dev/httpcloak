package fingerprint

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Firefox's HTTP/2 priorities, captured from release builds 133.0, 148.0 and
// 152.0.6 loading one page with every resource type below. The three builds
// agree on every entry. Firefox presets used to inherit Chrome's table and
// sent document at 256, an image at 183 and a fetch at 220, all exclusive,
// with Chrome's priority headers; real Firefox sends 42, 12 and 22, never
// exclusive, with headers of its own.
func TestFirefoxPriorityTableFollowsTheCaptures(t *testing.T) {
	want := map[string]struct {
		weight uint16
		header string
	}{
		"document": {42, "u=0, i"},
		"style":    {22, "u=2"},
		"script":   {22, "u=2"},
		"image":    {12, "u=5, i"},
		"font":     {32, ""},
		"iframe":   {22, "u=4"},
		"empty":    {22, "u=4"},
	}
	for _, name := range []string{
		"firefox-133", "firefox-148", "firefox-latest",
		"firefox-148-windows", "firefox-148-linux", "firefox-148-macos",
	} {
		p := GetStrict(name)
		if p == nil {
			t.Errorf("%s not registered", name)
			continue
		}
		if m := p.H2PriorityModel(); m != PriorityModelTable {
			t.Errorf("%s: priority model %q, want %q", name, m, PriorityModelTable)
		}
		for dest, w := range want {
			weight, excl, header, ok := p.H2PriorityFor(dest)
			if !ok {
				t.Errorf("%s/%s: not in the table", name, dest)
				continue
			}
			if weight != w.weight || header != w.header || excl {
				t.Errorf("%s/%s: weight %d header %q exclusive %v, want %d %q false",
					name, dest, weight, header, excl, w.weight, w.header)
			}
		}
		// A dest Firefox was not captured on falls back to the static weight,
		// rather than to a Chrome value.
		if _, _, _, ok := p.H2PriorityFor("worker"); ok {
			t.Errorf("%s: worker resolved from a table; Firefox was never captured on it", name)
		}
	}
}

// Chromium-family presets keep Chrome's derivation, exclusive flag and model.
func TestChromiumPresetsUseTheChromiumPriorityModel(t *testing.T) {
	for _, name := range []string{"chrome-155-windows", "chrome-146-windows", "chrome-133", "chrome-155-android"} {
		p := GetStrict(name)
		if p == nil {
			t.Errorf("%s not registered", name)
			continue
		}
		if m := p.H2PriorityModel(); m != PriorityModelChromium {
			t.Errorf("%s: priority model %q, want %q", name, m, PriorityModelChromium)
		}
		weight, excl, header, ok := p.H2PriorityFor("image")
		if !ok || weight != 183 || !excl || header != "u=2, i" {
			t.Errorf("%s/image: %d %v %q %v, want 183 true \"u=2, i\" true", name, weight, excl, header, ok)
		}
	}
	for _, name := range []string{"safari-18", "chrome-148-ios"} {
		if p := GetStrict(name); p != nil && p.H2PriorityModel() != PriorityModelTable {
			t.Errorf("%s: model %q; a preset without RFC 7540 priorities has no chain to build", name, p.H2PriorityModel())
		}
	}
}

// Which presets put their priority header on HTTP/1.1. Chromium sends none
// there and Firefox sends the HTTP/2 value; Chrome on iOS has the table model
// but no measurement says WebKit sends one, and it never has. Every registered
// preset is checked, so a new one cannot slip through on its name or model.
func TestHTTP1PriorityByPreset(t *testing.T) {
	for _, name := range Available() {
		p := GetStrict(name)
		if p == nil {
			continue
		}
		got := p.SendsPriorityOverHTTP1()
		switch {
		case strings.HasPrefix(p.Name, "firefox-"):
			if !got {
				t.Errorf("%s (%s): Firefox sends its priority header over HTTP/1.1", name, p.Name)
			}
		case strings.HasPrefix(p.Name, "chrome-"):
			if got {
				t.Errorf("%s (%s): a Chrome preset must not send a priority header over HTTP/1.1", name, p.Name)
			}
		}
	}
	custom := &Preset{Name: "my-preset", HTTP2Settings: HTTP2Settings{StreamExclusive: true}}
	if custom.SendsPriorityOverHTTP1() {
		t.Error("a preset on the Chromium priority model must not send it over HTTP/1.1, whatever its name")
	}

	// priority_over_http1 decides when set, over the model and the name, and
	// survives a load.
	for _, tc := range []struct {
		base string
		set  bool
	}{{"chrome-148-ios", true}, {"firefox-148-windows", false}} {
		js := fmt.Sprintf(`{"version": 1, "preset": {"name": "h1-prio-%v", "based_on": %q, "http2": {"priority_over_http1": %v}}}`,
			tc.set, tc.base, tc.set)
		p, err := LoadAndBuildPresetFromJSON([]byte(js))
		if err != nil {
			t.Fatalf("%s: %v", tc.base, err)
		}
		if got := p.SendsPriorityOverHTTP1(); got != tc.set {
			t.Errorf("%s with priority_over_http1 %v: got %v", tc.base, tc.set, got)
		}
	}
}

// The weight and the model survive describe -> load, so a custom preset made
// from a Firefox one stays Firefox.
func TestPriorityModelAndWeightRoundTrip(t *testing.T) {
	out, err := Describe("firefox-148-windows")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"priority_model": "table"`) || !strings.Contains(out, `"weight": 42`) {
		t.Fatalf("describe output lacks priority_model or weight:\n%s", out)
	}
	out = strings.Replace(out, `"name": "firefox-148-windows"`, `"name": "ff-roundtrip-copy"`, 1)
	p, err := LoadAndBuildPresetFromJSON([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if p.H2PriorityModel() != PriorityModelTable {
		t.Errorf("loaded copy: model %q", p.H2PriorityModel())
	}
	if w, excl, _, _ := p.H2PriorityFor("image"); w != 12 || excl {
		t.Errorf("loaded copy: image weight %d exclusive %v, want 12 false", w, excl)
	}
}

func TestPriorityModelAndWeightAreValidated(t *testing.T) {
	for _, bad := range []string{
		`"priority_model": "firefox"`,
		`"priority_table": {"image": {"urgency": 2, "incremental": true, "emit_header": true, "weight": 300}}`,
		`"priority_table": {"image": {"urgency": 9, "incremental": true, "emit_header": true}}`,
	} {
		js := `{"version": 1, "preset": {"name": "bad-prio", "based_on": "chrome-155-windows", "http2": {` + bad + `}}}`
		var probe map[string]any
		if err := json.Unmarshal([]byte(js), &probe); err != nil {
			t.Fatalf("test JSON is broken: %v", err)
		}
		if _, err := LoadAndBuildPresetFromJSON([]byte(js)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
