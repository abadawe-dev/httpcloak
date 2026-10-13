package httpcloak

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

// Issue #117, in the reporter's own shape: a session doing GETs against an
// HTTP/2 server that sends END_STREAM 50ms after the body. Every request used
// to end with RST_STREAM(CANCEL), on responses that had succeeded; a browser
// waits for END_STREAM and never resets them. The client package reads to EOF
// on its own path and was never affected; it is checked so it stays that way.
func TestSuccessfulResponsesAreNotReset(t *testing.T) {
	var resets, clean atomic.Int32
	body := []byte(strings.Repeat("x", 4096))
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(200)
		w.Write(body)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			resets.Add(1)
		case <-time.After(50 * time.Millisecond):
			clean.Add(1)
		}
	}))
	ts.EnableHTTP2 = true
	ts.TLS = &tls.Config{NextProtos: []string{"h2"}}
	ts.StartTLS()
	defer ts.Close()

	s := NewSession("chrome-latest", WithInsecureSkipVerify(), WithForceHTTP2(), WithoutRetry())
	defer s.Close()
	for i := 0; i < 5; i++ {
		resp, err := s.Get(context.Background(), ts.URL)
		if err != nil {
			t.Fatalf("session request %d: %v", i, err)
		}
		if b, _ := resp.Bytes(); len(b) != len(body) {
			t.Fatalf("session request %d: %d bytes", i, len(b))
		}
		time.Sleep(80 * time.Millisecond)
	}
	if resets.Load() != 0 {
		t.Errorf("session: %d of 5 successful responses were reset", resets.Load())
	}

	resets.Store(0)
	c := client.NewClient("chrome-latest", client.WithForceHTTP2(), client.WithInsecureSkipVerify())
	defer c.Close()
	for i := 0; i < 5; i++ {
		resp, err := c.Do(context.Background(), &client.Request{Method: "GET", URL: ts.URL})
		if err != nil {
			t.Fatalf("client request %d: %v", i, err)
		}
		if b, _ := resp.Bytes(); len(b) != len(body) {
			t.Fatalf("client request %d: %d bytes", i, len(b))
		}
		time.Sleep(80 * time.Millisecond)
	}
	if resets.Load() != 0 {
		t.Errorf("client: %d of 5 successful responses were reset", resets.Load())
	}
}
