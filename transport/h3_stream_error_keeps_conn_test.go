package transport

import (
	"context"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
)

// A stream error on a live HTTP/3 connection, here the server resetting each
// request, used to drop the connection from the pool without closing it.
// Keep-alives kept it from idling out, so every failed request left a
// connection and, since each connection has its own UDP socket, a file
// descriptor behind until the transport closed. The connection now stays in
// the pool and carries the next request.
func TestHTTP3StreamErrorKeepsTheConnection(t *testing.T) {
	origin := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		panic(shttp.ErrAbortHandler)
	}))
	tr := NewTransport("chrome-155-windows")
	tr.SetProtocol(ProtocolHTTP3)
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)

	const n = 10
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := tr.Do(ctx, &Request{Method: "GET", URL: origin + "/"})
		cancel()
		if err == nil {
			t.Fatal("request to a handler that resets every stream succeeded")
		}
	}
	if dials := tr.snapshot().h3.GetDialCount(); dials != 1 {
		t.Errorf("%d requests with a stream error dialed %d connections, want 1", n, dials)
	}
	h3 := tr.snapshot().h3
	h3.liveMu.Lock()
	sockets := len(h3.sockets)
	h3.liveMu.Unlock()
	if sockets > 1 {
		t.Errorf("%d UDP sockets open after %d stream errors on one origin, want 1", sockets, n)
	}
}
