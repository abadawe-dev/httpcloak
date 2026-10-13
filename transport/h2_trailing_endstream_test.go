package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Issue #117. A server that sends the whole body and then END_STREAM a little
// later, in an empty DATA frame, is common. The Content-Length fast path read
// exactly N bytes and closed the body without ever reading the EOF, so the
// close raced the trailing frame and usually lost: the stream was reset with
// RST_STREAM(CANCEL) on a response that had succeeded. The server sees that
// as a cancel. Chrome never does it, because it does not treat a response as
// finished until END_STREAM arrives.
//
// The server detects the reset the way any HTTP/2 server would: a stream reset
// cancels the handler's request context, a clean end does not.
func startTrailingEndStreamServer(t *testing.T, resets, clean *atomic.Int32) *httptest.Server {
	return startTrailingEndStreamServerDelay(t, resets, clean, 50*time.Millisecond)
}

func startTrailingEndStreamServerDelay(t *testing.T, resets, clean *atomic.Int32, delay time.Duration) *httptest.Server {
	t.Helper()
	body := []byte(strings.Repeat("x", 4096))
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(200)
		w.Write(body)
		w.(http.Flusher).Flush() // body on the wire, END_STREAM not yet
		select {
		case <-r.Context().Done():
			resets.Add(1)
		case <-time.After(delay):
			clean.Add(1) // returning sends the trailing END_STREAM
		}
	}))
	ts.EnableHTTP2 = true
	ts.TLS = &tls.Config{NextProtos: []string{"h2"}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func TestContentLengthBodyDoesNotResetTheStream(t *testing.T) {
	var resets, clean atomic.Int32
	ts := startTrailingEndStreamServer(t, &resets, &clean)

	tr := NewTransport("chrome-155-windows")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	// 40 rather than a handful: two of the ways this went wrong were races
	// that hit about one request in a hundred (our END_STREAM flag recorded
	// after the response was already read, and a context cancel winning a
	// select against the linger), so few requests would rarely catch them.
	const n = 40
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: ts.URL})
		cancel()
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if b, _ := resp.Bytes(); len(b) != 4096 {
			t.Fatalf("request %d: %d body bytes, want 4096", i, len(b))
		}
		resp.Body.Close()
		time.Sleep(80 * time.Millisecond) // let the handler reach its verdict
	}
	if resets.Load() != 0 || clean.Load() != n {
		t.Errorf("streams reset %d, clean %d of %d; a complete response must not be "+
			"cancelled with RST_STREAM", resets.Load(), clean.Load(), n)
	}
}

// Reading exactly the declared length from a stream and closing it is the
// same finished response, and must end the same way.
func TestStreamedContentLengthBodyDoesNotResetTheStream(t *testing.T) {
	var resets, clean atomic.Int32
	ts := startTrailingEndStreamServer(t, &resets, &clean)
	tr := NewTransport("chrome-155-windows")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sr, err := tr.DoStream(ctx, &Request{Method: "GET", URL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(sr, buf); err != nil {
		t.Fatal(err)
	}
	sr.Close()
	time.Sleep(120 * time.Millisecond)
	if resets.Load() != 0 || clean.Load() != 1 {
		t.Errorf("streams reset %d, clean %d; want 0 and 1", resets.Load(), clean.Load())
	}
}

// Closing a body with bytes still unread is a real early close, and still
// resets the stream at once. Otherwise the fix above would just be resets
// switched off.
func TestEarlyCloseStillResetsTheStream(t *testing.T) {
	var resets, clean atomic.Int32
	ts := startTrailingEndStreamServerDelay(t, &resets, &clean, 2*time.Second)
	tr := NewTransport("chrome-155-windows")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sr, err := tr.DoStream(ctx, &Request{Method: "GET", URL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	io.ReadFull(sr, make([]byte, 100))
	sr.Close()
	time.Sleep(300 * time.Millisecond)
	if resets.Load() != 1 {
		t.Errorf("an early close left the stream open (resets %d, clean %d)", resets.Load(), clean.Load())
	}
}

// A peer that never sends END_STREAM cannot hold the stream for the life of
// the connection: it is reset once the linger runs out (10s).
func TestLingeringStreamIsResetEventually(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 10s linger")
	}
	var resets, clean atomic.Int32
	ts := startTrailingEndStreamServerDelay(t, &resets, &clean, 30*time.Second)
	tr := NewTransport("chrome-155-windows")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: ts.URL})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(5 * time.Second)
	if resets.Load() != 0 {
		t.Fatalf("reset after 5s; the linger is 10s")
	}
	time.Sleep(6500 * time.Millisecond)
	if resets.Load() != 1 {
		t.Errorf("not reset after the linger ran out (resets %d)", resets.Load())
	}
}
