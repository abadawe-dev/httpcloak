package transport

import (
	"bufio"
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Over HTTP/1.1, Chromium sends no priority header and Firefox sends the one
// it sends over HTTP/2, per resource type; both measured against the real
// browsers with an http/1.1-only server. The table used to be skipped on
// HTTP/1.1, so Firefox sent the CORS value on every subresource. Chrome on iOS
// runs on WebKit and takes the table model, and still sends none there; see
// Preset.SendsPriorityOverHTTP1.
func TestPriorityHeaderOverHTTP1(t *testing.T) {
	base := startH2CaptureServer(t) // for its certificate only
	base.listener.Close()
	cfg := base.tlsConfig.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					prio := ""
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l == "\r\n" {
							break
						}
						if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "priority") {
							prio = strings.TrimSpace(v)
						}
					}
					got <- prio
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()

	dests := []string{"document", "image", "script", "style", "empty"}
	want := map[string][]string{
		"chrome-155-windows":  {"", "", "", "", ""},
		"android-chrome-148":  {"", "", "", "", ""},
		"chrome-148-ios":      {"", "", "", "", ""},
		"firefox-148-windows": {"u=0, i", "u=5, i", "u=2", "u=2", "u=4"},
	}
	for preset, w := range want {
		tr := NewTransport(preset)
		tr.SetProtocol(ProtocolHTTP1)
		tr.SetInsecureSkipVerify(true)
		for i, dest := range dests {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + ln.Addr().String() + "/",
				Headers: map[string][]string{"Sec-Fetch-Dest": {dest}}})
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, dest, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if p := <-got; p != w[i] {
				t.Errorf("%s dest %s over HTTP/1.1: priority %q, want %q", preset, dest, p, w[i])
			}
		}
		tr.Close()
	}
}
