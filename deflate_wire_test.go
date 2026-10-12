package httpcloak

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

// Content-Encoding: deflate end to end, through every public path that decodes
// a body: the session's buffered and streaming responses, and the client
// package's buffered and streaming responses (#115).
//
// RFC 9110 defines deflate as the zlib format, and that framing used to fail on
// every path because each one read raw deflate only. The client package's
// streaming path did not decode deflate at all and returned the compressed
// bytes. Both framings must now come back as the original text everywhere.
func TestDeflateBodiesDecodeOnEveryPath(t *testing.T) {
	want := strings.Repeat("deflate body, decoded on every path. ", 300)

	var zbuf, rbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zw.Write([]byte(want))
	zw.Close()
	rw, _ := flate.NewWriter(&rbuf, flate.DefaultCompression)
	rw.Write([]byte(want))
	rw.Close()
	bodies := map[string][]byte{"/zlib": zbuf.Bytes(), "/raw": rbuf.Bytes()}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "deflate")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(b)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess := NewSession("chrome-latest", WithInsecureSkipVerify(), WithForceHTTP1())
	defer sess.Close()
	cl := client.NewClient("chrome-latest", client.WithInsecureSkipVerify(), client.WithForceHTTP1())
	defer cl.Close()

	paths := map[string]func(url string) (string, error){
		"session buffered": func(url string) (string, error) {
			r, err := sess.Get(ctx, url)
			if err != nil {
				return "", err
			}
			defer r.Body.Close()
			b, err := io.ReadAll(r.Body)
			return string(b), err
		},
		"session stream": func(url string) (string, error) {
			r, err := sess.GetStream(ctx, url)
			if err != nil {
				return "", err
			}
			b, err := r.ReadAll()
			return string(b), err
		},
		"client buffered": func(url string) (string, error) {
			r, err := cl.Get(ctx, url, nil)
			if err != nil {
				return "", err
			}
			b, err := r.Bytes()
			return string(b), err
		},
		"client stream": func(url string) (string, error) {
			r, err := cl.GetStream(ctx, url, nil)
			if err != nil {
				return "", err
			}
			b, err := r.ReadAll()
			return string(b), err
		},
	}
	for pathName, fetch := range paths {
		for framing := range bodies {
			got, err := fetch(srv.URL + framing)
			if err != nil {
				t.Errorf("%s, %s framing: %v", pathName, framing[1:], err)
				continue
			}
			if got != want {
				t.Errorf("%s, %s framing: got %d bytes that are not the original text", pathName, framing[1:], len(got))
			}
		}
	}
}
