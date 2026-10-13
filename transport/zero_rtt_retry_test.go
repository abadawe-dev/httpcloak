package transport

import (
	"testing"

	tls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// A retry after a 0-RTT rejection has to differ from the attempt that failed.
// It used to try that by dropping the session cache from the config handed to
// the dial wrapper, but every dial path ignored that config, cloned its own,
// put the cache back and chose the resuming hello anyway, so the retries
// offered early data again and were rejected again (#127). The ticket itself
// is now evicted, which every dial path sees.
//
// tls.ClientSessionCache says a nil Put removes the entry. Ours stored a nil
// entry instead, so Get reported a session that did not exist and the
// resuming hello was chosen with nothing to resume.
func TestEvictedTicketMeansAFullHandshakeHello(t *testing.T) {
	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	tr.sessionCache.Put("rejects-early-data.example", &tls.ClientSessionState{})
	tr.sessionCache.Put("other-host.example", &tls.ClientSessionState{})
	if !tr.hasSessionForHost("rejects-early-data.example") {
		t.Fatal("ticket not stored; the rest of this test would pass for the wrong reason")
	}
	if !specHasPSK(t, tr, "rejects-early-data.example") {
		t.Fatal("a host with a ticket did not get the resuming hello")
	}

	tr.sessionCache.Put("rejects-early-data.example", nil) // what the rejection path does

	if tr.hasSessionForHost("rejects-early-data.example") {
		t.Error("Put(nil) left an entry behind; the next dial will still try to resume")
	}
	if specHasPSK(t, tr, "rejects-early-data.example") {
		t.Error("an evicted host still got the resuming hello")
	}
	if !tr.hasSessionForHost("other-host.example") || !specHasPSK(t, tr, "other-host.example") {
		t.Error("evicting one host's ticket touched another's")
	}
}

func specHasPSK(t *testing.T, tr *HTTP3Transport, host string) bool {
	t.Helper()
	spec, err := tr.resolveQUICSpec(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range spec.Extensions {
		if _, ok := e.(*tls.UtlsPreSharedKeyExtension); ok {
			return true
		}
	}
	return false
}
