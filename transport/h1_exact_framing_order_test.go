package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// ExactHeaders includes protocol framing when explicitly listed: native clients
// can send UA before Host, and Connection belongs at the caller's slot rather
// than being hoisted to Chrome's fixed second position. Default requests retain
// the normal browser prefix, and omitted Host is still supplied as framing.
func TestH1ExactHeadersKeepExplicitHostAndConnectionPositions(t *testing.T) {
	cases := []struct {
		name string
		keys []string
	}{
		{"native order", []string{"User-Agent", "Host", "Connection", "Accept-Encoding"}},
		{"exact framing casing", []string{"user-agent", "host", "connection", "accept-encoding"}},
		{"late connection", []string{"User-Agent", "Host", "Accept-Encoding", "Connection"}},
		{"implicit host", []string{"User-Agent", "Accept-Encoding"}},
		{"default browser", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			authority := listener.Addr().String()
			type capture struct {
				lines []string
				err   error
			}
			captured := make(chan capture, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					captured <- capture{err: err}
					return
				}
				defer conn.Close()
				reader := bufio.NewReader(conn)
				var lines []string
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						captured <- capture{err: err}
						return
					}
					if line == "\r\n" {
						break
					}
					lines = append(lines, strings.TrimSuffix(line, "\r\n"))
				}
				_, err = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				captured <- capture{lines, err}
			}()
			var exact []fingerprint.HeaderPair
			values := map[string]string{"user-agent": "NativeSDK/1", "host": authority, "connection": "Keep-Alive", "accept-encoding": "gzip"}
			for _, key := range tc.keys {
				exact = append(exact, fingerprint.HeaderPair{Key: key, Value: values[strings.ToLower(key)]})
			}
			tr := NewTransport("chrome-146")
			tr.SetProtocol(ProtocolHTTP1)
			t.Cleanup(tr.Close)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := tr.Do(ctx, &Request{Method: "GET", URL: "http://" + authority + "/sample?q=1", ExactHeaders: exact}); err != nil {
				t.Fatal(err)
			}
			got := <-captured
			if got.err != nil {
				t.Fatal(got.err)
			}
			if got.lines[0] != "GET /sample?q=1 HTTP/1.1" {
				t.Fatalf("request line = %q", got.lines[0])
			}
			if tc.keys == nil {
				if !slices.Equal(got.lines[1:3], []string{"Host: " + authority, "Connection: keep-alive"}) {
					t.Fatalf("default browser prefix changed: %v", got.lines)
				}
				return
			}
			var want []string
			if !slices.Contains(tc.keys, "Host") && !slices.Contains(tc.keys, "host") {
				want = append(want, "Host: "+authority)
			}
			for _, pair := range exact {
				want = append(want, pair.Key+": "+pair.Value)
			}
			if !slices.Equal(got.lines[1:], want) {
				t.Fatalf("headers = %q, want %q", got.lines[1:], want)
			}
		})
	}
}
