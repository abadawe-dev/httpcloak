package transport

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	shttp "github.com/sardanioss/http"
)

// StreamResponse.Close closes the body before cancelling the stream context,
// so a fully read HTTP/2 body can wait for END_STREAM instead of being reset
// (#117). That order must not make closing an endless stream hang on any
// protocol: a body that drains on Close would now block where the cancel used
// to cut it short.
func TestClosingAnEndlessStreamReturns(t *testing.T) {
	// The body is compressed with whatever the request's ?enc= names: the
	// decoders sit between Close and the body, and zstd's in particular waits
	// for its pending read when it is closed.
	serve := func(w io.Writer, flush func(), done <-chan struct{}, enc string) {
		var cw io.Writer = w
		var cflush func() error
		switch enc {
		case "gzip":
			z := gzip.NewWriter(w)
			cw, cflush = z, z.Flush
		case "deflate":
			z, _ := flate.NewWriter(w, flate.DefaultCompression)
			cw, cflush = z, z.Flush
		case "br":
			z := brotli.NewWriter(w)
			cw, cflush = z, z.Flush
		case "zstd":
			z, _ := zstd.NewWriter(w)
			cw, cflush = z, z.Flush
		}
		for {
			if _, err := cw.Write([]byte("data: tick\n\n")); err != nil {
				return
			}
			if cflush != nil {
				if cflush() != nil {
					return
				}
			}
			flush()
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	endless := func(w http.ResponseWriter, r *http.Request) {
		enc := r.URL.Query().Get("enc")
		if enc != "" {
			w.Header().Set("Content-Encoding", enc)
		}
		w.WriteHeader(200)
		serve(w, w.(http.Flusher).Flush, r.Context().Done(), enc)
	}

	h1 := httptest.NewUnstartedServer(http.HandlerFunc(endless))
	h1.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	h1.StartTLS()
	defer h1.Close()
	h2 := httptest.NewUnstartedServer(http.HandlerFunc(endless))
	h2.EnableHTTP2 = true
	h2.TLS = &tls.Config{NextProtos: []string{"h2"}}
	h2.StartTLS()
	defer h2.Close()
	h3 := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		enc := r.URL.Query().Get("enc")
		if enc != "" {
			w.Header().Set("Content-Encoding", enc)
		}
		w.WriteHeader(200)
		serve(w, w.(shttp.Flusher).Flush, r.Context().Done(), enc)
	}))

	for _, tc := range []struct {
		name  string
		proto Protocol
		url   string
	}{
		{"h1", ProtocolHTTP1, h1.URL},
		{"h2", ProtocolHTTP2, h2.URL},
		{"h3", ProtocolHTTP3, h3},
	} {
		for _, enc := range []string{"", "gzip", "deflate", "br", "zstd"} {
			name := tc.name
			if enc != "" {
				name += "/" + enc
			}
			t.Run(name, func(t *testing.T) {
				tr := NewTransport("chrome-155-windows")
				tr.SetProtocol(tc.proto)
				tr.SetInsecureSkipVerify(true)
				defer tr.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				sr, err := tr.DoStream(ctx, &Request{Method: "GET", URL: tc.url + "/?enc=" + enc})
				if err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				n, err := sr.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(string(buf[:n]), "data: tick") {
					t.Fatalf("read %q; the body was not decoded", buf[:n])
				}
				done := make(chan struct{})
				start := time.Now()
				go func() { sr.Close(); close(done) }()
				select {
				case <-done:
					if d := time.Since(start); d > time.Second {
						t.Errorf("Close took %v", d)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("Close on an endless stream did not return")
				}
			})
		}
	}
}
