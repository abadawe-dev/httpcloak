package transport

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
)

// A host this session has been to over HTTP/3 holds a session ticket, and the
// next connection to it resumes with early data, so its dial returns before
// the handshake completes. When the path has since stopped carrying UDP, that
// handshake never completes. The request waited for it on nothing but its own
// deadline, reported a request that never left as possibly sent, and left the
// dead connection pooled, so every later request to the host waited out its
// deadline too. It now fails when QUIC gives up on the handshake, as not sent,
// and the host's next request opens a new connection.
func TestARequestOnAHandshakeThatNeverCompletesWasNotSent(t *testing.T) {
	gate, url := gatedH3Origin(t, func(w shttp.ResponseWriter, r *shttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("ok"))
	})
	tr := h3Transport(t, ProtocolHTTP3)

	if _, err := tr.Do(context.Background(), &Request{URL: url}); err != nil {
		t.Fatalf("first visit: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // the ticket arrives after the answer
	tr.h3Transport.closeOrigin(fmt.Sprintf("127.0.0.1:%d", gate.port()))

	gate.blocked.Store(true)
	start := time.Now()
	_, err := tr.Do(context.Background(), &Request{Method: "POST", URL: url + "order", Body: []byte("qty=1"), Timeout: 20 * time.Second})
	took := time.Since(start)
	if err == nil {
		t.Fatal("the POST went through a black-holed path")
	}
	if !RequestNotSent(err) {
		t.Fatalf("a POST that never left was reported as possibly sent (after %v): %v", took, err)
	}
	if took > 15*time.Second {
		t.Fatalf("the POST took %v to fail: it waited out its deadline on a handshake that had died", took)
	}

	gate.blocked.Store(false)
	start = time.Now()
	resp, err := tr.Do(context.Background(), &Request{URL: url, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("once the path came back, the next request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the next request took %v: it was held on the dead connection", took)
	}
}

// Auto mode's connect race used to probe HTTP/3 on a connection of its own,
// close it (with a "connect probe" reason the server reads), and send the
// request on a second connection: two handshakes per new host where a browser
// makes one. The probe's connection now carries the request.
func TestTheConnectRaceConnectionCarriesTheRequest(t *testing.T) {
	url, _ := slowH3Origin(t, func(string, int32) time.Duration { return 0 })
	tr := h3Transport(t, ProtocolAuto)

	resp, err := tr.Do(context.Background(), &Request{URL: url, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Protocol != "h3" {
		t.Fatalf("served over %s, want h3", resp.Protocol)
	}
	if dials := tr.h3Transport.GetDialCount(); dials != 1 {
		t.Fatalf("%d QUIC connections for one request, want 1", dials)
	}
}
