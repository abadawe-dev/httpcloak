package transport

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/h2build"
)

// ExactHeaders promises that nothing is added, but on HTTP/2 the transport
// appended "accept-encoding: gzip" to any request without one, as Go's does,
// and quietly gunzipped the answer. HTTP/1.1 never did. The HTTP/2 and HTTP/3
// transports no longer add it on anyone's behalf.
func TestExactHeadersGetNoAddedAcceptEncoding(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]string{}
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		mu.Lock()
		got[r.Proto] = r.Header.Values("Accept-Encoding")
		mu.Unlock()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	for _, p := range []Protocol{ProtocolHTTP1, ProtocolHTTP2} {
		tr := NewTransport("chrome-latest")
		tr.SetInsecureSkipVerify(true)
		tr.SetProtocol(p)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := tr.Do(ctx, &Request{Method: "GET", URL: srv.URL,
			ExactHeaders: []fingerprint.HeaderPair{{Key: "x-only", Value: "1"}}})
		cancel()
		tr.Close()
		if err != nil {
			t.Fatalf("%v: %v", p, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		if v, ok := got[proto]; !ok {
			t.Errorf("no %s request reached the server", proto)
		} else if len(v) != 0 {
			t.Errorf("%s request carried Accept-Encoding %q; ExactHeaders sent none", proto, v)
		}
	}
}

// The HTTP/3 transports are built in two places; both must leave
// Accept-Encoding alone too. Asserted on what is built, since a local QUIC
// server is a lot of machinery for one boolean.
func TestTransportsNeverRequestCompression(t *testing.T) {
	if !h2build.Transport(h2build.Options{Preset: fingerprint.Get("chrome-latest")}).DisableCompression {
		t.Error("the HTTP/2 transport adds accept-encoding: gzip to requests without one")
	}
	h3, err := NewHTTP3Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	defer h3.Close()
	if b := h3.buildHTTP3Transport(nil, nil); !b.DisableCompression {
		t.Error("the HTTP/3 transport adds accept-encoding: gzip to requests without one")
	}
}
