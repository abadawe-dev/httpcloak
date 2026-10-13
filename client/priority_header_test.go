package client

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// The priority header and HTTP/2 priority the client sends per fetch mode,
// against captures: Chrome 155 and Firefox 133, 148 and 152 loading a page
// with each resource type. The client used to hardcode Chrome's values in its
// mode helpers, so Firefox presets sent Chrome's headers and weights, and
// no-cors requests sent no priority header at all, where Chrome sends one.

type prioCase struct {
	name string
	mode FetchMode
	dest string
}

var prioModes = []prioCase{
	{"navigate", FetchModeNavigate, ""},
	{"cors", FetchModeCORS, ""},
	{"no-cors image", FetchModeNoCors, "image"},
	{"no-cors script", FetchModeNoCors, "script"},
	{"no-cors style", FetchModeNoCors, "style"},
}

func priorityTLSListener(t *testing.T, alpn string) net.Listener {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{alpn},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

type h2Seen struct {
	priority string
	weight   int
	excl     bool
}

func startPriorityH2Server(t *testing.T) (string, <-chan h2Seen) {
	ln := priorityTLSListener(t, "h2")
	got := make(chan h2Seen, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := io.ReadFull(c, make([]byte, 24)); err != nil {
					return
				}
				fr := http2.NewFramer(c, c)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					switch f := f.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							fr.WriteSettingsAck()
						}
					case *http2.MetaHeadersFrame:
						seen := h2Seen{weight: int(f.Priority.Weight) + 1, excl: f.Priority.Exclusive}
						for _, hf := range f.Fields {
							if hf.Name == "priority" {
								seen.priority = hf.Value
							}
						}
						got <- seen
						var b strings.Builder
						hpack.NewEncoder(&b).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID,
							BlockFragment: []byte(b.String()), EndHeaders: true, EndStream: true})
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), got
}

func TestClientPriorityPerFetchModeOverHTTP2(t *testing.T) {
	want := map[string]map[string]h2Seen{
		"chrome-155-windows": {
			"navigate":       {"u=0, i", 256, true},
			"cors":           {"u=1, i", 220, true},
			"no-cors image":  {"u=2, i", 183, true},
			"no-cors script": {"u=1", 220, true},
			"no-cors style":  {"u=0", 256, true},
		},
		"firefox-148-windows": {
			"navigate":       {"u=0, i", 42, false},
			"cors":           {"u=4", 22, false},
			"no-cors image":  {"u=5, i", 12, false},
			"no-cors script": {"u=2", 22, false},
			"no-cors style":  {"u=2", 22, false},
		},
	}
	addr, got := startPriorityH2Server(t)
	for preset, cases := range want {
		c := NewClient(preset, WithForceHTTP2(), WithInsecureSkipVerify())
		for _, m := range prioModes {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := c.Do(ctx, &Request{Method: "GET", URL: "https://" + addr + "/", FetchMode: m.mode, FetchDest: m.dest})
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, m.name, err)
			}
			if s, w := <-got, cases[m.name]; s != w {
				t.Errorf("%s %s: priority %q weight %d exclusive %v, want %q %d %v",
					preset, m.name, s.priority, s.weight, s.excl, w.priority, w.weight, w.excl)
			}
		}
		c.Close()
	}
}

// Chromium sends no priority header over HTTP/1.1; Firefox sends the same one
// it sends over HTTP/2. Both measured against the real browsers with an
// http/1.1-only server. The client sent Chrome's header over HTTP/1.1.
func TestClientPriorityOverHTTP1(t *testing.T) {
	ln := priorityTLSListener(t, "http/1.1")
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
	want := map[string][]string{
		"chrome-155-windows":  {"", "", "", "", ""},
		"android-chrome-148":  {"", "", "", "", ""},
		"firefox-148-windows": {"u=0, i", "u=4", "u=5, i", "u=2", "u=2"},
	}
	for preset, w := range want {
		c := NewClient(preset, WithForceHTTP1(), WithInsecureSkipVerify())
		for i, m := range prioModes {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := c.Do(ctx, &Request{Method: "GET", URL: "https://" + ln.Addr().String() + "/", FetchMode: m.mode, FetchDest: m.dest})
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, m.name, err)
			}
			if p := <-got; p != w[i] {
				t.Errorf("%s %s over HTTP/1.1: priority %q, want %q", preset, m.name, p, w[i])
			}
		}
		c.Close()
	}
}
