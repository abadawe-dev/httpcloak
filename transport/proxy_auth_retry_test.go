package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A permanent proxy response is the answer, even if a later dial might fail
// differently. Exercise the actual CONNECT paths, not only the retry helper.
func TestProxyAuthenticationRefusalIsNotRetried(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolHTTP1, ProtocolHTTP2} {
		t.Run(protocol.String(), func(t *testing.T) {
			var attempts atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" {
					t.Errorf("method %s, want CONNECT", r.Method)
				}
				attempts.Add(1)
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusProxyAuthRequired)
			}))
			defer proxy.Close()
			tr := NewTransportWithConfig("chrome-146", &ProxyConfig{URL: proxy.URL}, nil)
			tr.SetProtocol(protocol)
			defer tr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://example.com/"})
			var status *ProxyStatusError
			if !errors.As(err, &status) || status.StatusCode != 407 {
				t.Fatalf("want typed proxy407, got %v", err)
			}
			if n := attempts.Load(); n != 1 {
				t.Fatalf("proxy authentication was retried: %d CONNECTs", n)
			}
		})
	}
}

func TestTransientProxyFailuresRemainRetryable(t *testing.T) {
	for _, code := range []int{408, 429, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var attempts int
			_, err := retryDial(context.Background(), 2, time.Second, func(context.Context) (net.Conn, error) {
				attempts++
				return nil, &ProxyStatusError{StatusCode: code, Status: http.StatusText(code)}
			})
			var status *ProxyStatusError
			if !errors.As(err, &status) || status.StatusCode != code || attempts != 2 {
				t.Fatalf("status=%v attempts=%d", err, attempts)
			}
		})
	}
}
