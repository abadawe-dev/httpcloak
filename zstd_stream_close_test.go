package httpcloak

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/sardanioss/httpcloak/client"
)

// Closing a zstd stream before its end must release the decoder (#118).
//
// The zstd decoder runs goroutines until it is closed, and both stream paths
// returned it as the reader with a nil closer, so StreamResponse.Close never
// closed it. Reading to the end hid that, since the decoder stops at EOF.
// Stopping early, which is most of why anyone streams, left two or three
// goroutines behind per stream: measured 39 over 20 session streams and 55 over
// 20 client streams before the fix, 0 after.
func TestZstdStreamClosedEarlyReleasesTheDecoder(t *testing.T) {
	raw := make([]byte, 4<<20)
	rand.Read(raw[:1<<20])
	var buf bytes.Buffer
	enc, _ := zstd.NewWriter(&buf)
	enc.Write(raw)
	enc.Close()
	body := buf.Bytes()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "zstd")
		w.Write(body)
	}))
	defer srv.Close()

	sess := NewSession("chrome-latest", WithInsecureSkipVerify(), WithForceHTTP1())
	defer sess.Close()
	cl := client.NewClient("chrome-latest", client.WithInsecureSkipVerify(), client.WithForceHTTP1())
	defer cl.Close()

	settle := func() int {
		for i := 0; i < 3; i++ {
			runtime.GC()
			time.Sleep(150 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}

	const streams = 20
	for _, tc := range []struct {
		name string
		open func(ctx context.Context) (interface {
			Read([]byte) (int, error)
			Close() error
		}, error)
	}{
		{"session", func(ctx context.Context) (interface {
			Read([]byte) (int, error)
			Close() error
		}, error) {
			return sess.GetStream(ctx, srv.URL)
		}},
		{"client", func(ctx context.Context) (interface {
			Read([]byte) (int, error)
			Close() error
		}, error) {
			return cl.GetStream(ctx, srv.URL, nil)
		}},
	} {
		base := settle()
		for i := 0; i < streams; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			s, err := tc.open(ctx)
			if err != nil {
				cancel()
				t.Fatalf("%s: open: %v", tc.name, err)
			}
			s.Read(make([]byte, 64))
			s.Close()
			cancel()
		}
		if leaked := settle() - base; leaked > streams/4 {
			t.Errorf("%s: %d goroutines left after closing %d zstd streams early; "+
				"the decoder is not being closed", tc.name, leaked, streams)
		}
	}
}
