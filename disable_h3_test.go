package httpcloak

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Issue #121. WithDisableHTTP3 is documented as "disables HTTP/3 while keeping
// H1/H2 auto-negotiation", but it was implemented as forcing HTTP/2, which
// skips the ALPN fallback auto mode has. An origin whose ALPN offers only
// http/1.1 was then unreachable: "ALPN mismatch: expected h2, got http/1.1".
// Disabling HTTP/3 is the usual setting behind an HTTP proxy, so the common
// proxied setup was the one that could not reach an HTTP/1.1-only site.
func TestDisableHTTP3KeepsTheHTTP1Fallback(t *testing.T) {
	for _, alpn := range [][]string{{"http/1.1"}, {"h2", "http/1.1"}} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Proto", r.Proto)
			w.WriteHeader(200)
		}))
		srv.EnableHTTP2 = len(alpn) == 2
		srv.TLS = &tls.Config{NextProtos: alpn}
		srv.StartTLS()

		for _, opts := range []struct {
			name string
			opt  []SessionOption
		}{
			{"auto", nil},
			{"disable-h3", []SessionOption{WithDisableHTTP3()}},
			{"disable-h3 fork", []SessionOption{WithDisableHTTP3()}},
		} {
			s := NewSession("chrome-155-windows", append(opts.opt, WithInsecureSkipVerify())...)
			if opts.name == "disable-h3 fork" {
				// Forks build their transport separately and had the same bug.
				parent := s
				s = parent.Fork(1)[0]
				defer parent.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := s.Do(ctx, &Request{Method: "GET", URL: srv.URL})
			cancel()
			if err != nil {
				t.Errorf("ALPN %v, %s: %v", alpn, opts.name, err)
			} else {
				t.Logf("ALPN %v, %s: %d over %s", alpn, opts.name, resp.StatusCode, resp.Protocol)
				resp.Close()
			}
			s.Close()
		}
		srv.Close()
	}
}
