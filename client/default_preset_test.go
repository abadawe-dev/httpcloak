package client

import (
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// NewClient("") overwrote the chrome-latest default with the empty name, which
// then resolved to chrome-146. See fingerprint.TestEmptyPresetNameIsChromeLatest.
func TestNewClientWithoutPresetUsesChromeLatest(t *testing.T) {
	c := NewClient("")
	defer c.Close()
	if want := fingerprint.Get("chrome-latest").Name; c.preset.Name != want {
		t.Fatalf(`NewClient("") uses %s, want %s`, c.preset.Name, want)
	}
}
