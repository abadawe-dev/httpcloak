package main

import (
	"testing"
	"time"

	"github.com/sardanioss/httpcloak"
)

// The synchronous entry points used to bound a request without a timeout of
// its own at a flat 30s, cutting short a session configured with a longer one.
// That bit hardest on a restored session, whose timeout a binding has no way
// to read back and pass explicitly.
func TestSessionDefaultTimeoutFollowsTheSession(t *testing.T) {
	session := httpcloak.NewSession("chrome-146", httpcloak.WithSessionTimeout(90*time.Second))
	defer session.Close()
	if got := sessionDefaultTimeout(session); got != 90*time.Second {
		t.Errorf("configured session: got %v, want 90s", got)
	}

	data, err := session.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := httpcloak.UnmarshalSession(data)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got := sessionDefaultTimeout(restored); got != 90*time.Second {
		t.Errorf("restored session: got %v, want 90s", got)
	}
}

func TestSessionDefaultTimeoutIs30sByDefault(t *testing.T) {
	session := httpcloak.NewSession("chrome-146")
	defer session.Close()
	if got := sessionDefaultTimeout(session); got != 30*time.Second {
		t.Errorf("got %v, want 30s", got)
	}
}
