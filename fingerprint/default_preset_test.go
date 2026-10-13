package fingerprint

import "testing"

// An empty preset name is the default preset everywhere. Sessions already
// mapped it to chrome-latest, while Get, which the client and the transport
// use, answered it with chrome-146, so httpcloak.New("") sent a fingerprint
// nine versions behind the one the docs promise.
func TestEmptyPresetNameIsChromeLatest(t *testing.T) {
	got, want := Get(""), Get("chrome-latest")
	if got.Name != want.Name || got.UserAgent != want.UserAgent {
		t.Fatalf(`Get("") = %s (%s), want chrome-latest's %s (%s)`, got.Name, got.UserAgent, want.Name, want.UserAgent)
	}
	if p := Get("no-such-preset"); p.Name != Chrome146().Name {
		t.Errorf("unknown name now resolves to %s; only the empty name changed", p.Name)
	}
}
