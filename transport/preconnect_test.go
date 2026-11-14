package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Preconnect opens the connection the next request to a host goes out on, and
// sends nothing a server reads as a request; a second Preconnect, or the
// request itself, opens no other.
func TestPreconnectOpensTheConnectionTheRequestUses(t *testing.T) {
	t.Run("HTTP/2", func(t *testing.T) {
		var requests atomic.Int32
		srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			requests.Add(1)
			w.Write([]byte("ok"))
		}))
		l := &countingListener{Listener: srv.Listener}
		srv.Listener = l
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)

		for _, c := range []struct {
			name  string
			proxy bool
		}{{"direct", false}, {"through a CONNECT proxy", true}} {
			t.Run(c.name, func(t *testing.T) {
				var proxy *ProxyConfig
				if c.proxy {
					proxy = &ProxyConfig{URL: connectProxy(t, "")}
				}
				tr := NewTransportWithConfig("firefox-148", proxy, nil)
				tr.SetInsecureSkipVerify(true)
				t.Cleanup(tr.Close)
				before, asked := l.accepted.Load(), requests.Load()

				ctx := context.Background()
				for range 2 {
					if err := tr.Preconnect(ctx, srv.URL+"/checkout"); err != nil {
						t.Fatal(err)
					}
				}
				if n := l.accepted.Load() - before; n != 1 {
					t.Fatalf("%d connections opened by two preconnects, want 1", n)
				}
				if n := requests.Load() - asked; n != 0 {
					t.Fatalf("the server read %d requests from a preconnect", n)
				}
				resp, err := tr.Do(ctx, &Request{URL: srv.URL + "/checkout"})
				if err != nil {
					t.Fatal(err)
				}
				if resp.Protocol != "h2" {
					t.Fatalf("served over %s, want h2", resp.Protocol)
				}
				if n := l.accepted.Load() - before; n != 1 {
					t.Fatalf("the request opened a connection of its own (%d in all)", n)
				}
			})
		}
	})

	t.Run("HTTP/3", func(t *testing.T) {
		url, seen := slowH3Origin(t, func(string, int32) time.Duration { return 0 })
		for _, proto := range []Protocol{ProtocolHTTP3, ProtocolAuto} {
			t.Run(proto.String(), func(t *testing.T) {
				tr := h3Transport(t, proto)
				if proto == ProtocolAuto {
					tr.cacheProtocol(extractHost(url), ProtocolHTTP3)
				}
				asked := seen("GET")
				ctx := context.Background()
				for range 2 {
					if err := tr.Preconnect(ctx, url); err != nil {
						t.Fatal(err)
					}
				}
				if n := tr.h3Transport.GetDialCount(); n != 1 {
					t.Fatalf("%d QUIC connections opened by two preconnects, want 1", n)
				}
				if n := seen("GET") - asked; n != 0 {
					t.Fatalf("the server read %d requests from a preconnect", n)
				}
				resp, err := tr.Do(ctx, &Request{URL: url})
				if err != nil {
					t.Fatal(err)
				}
				if resp.Protocol != "h3" {
					t.Fatalf("served over %s, want h3", resp.Protocol)
				}
				if n := tr.h3Transport.GetDialCount(); n != 1 {
					t.Fatalf("the request opened a QUIC connection of its own (%d in all)", n)
				}
			})
		}
	})

	t.Run("HTTP/1.1", func(t *testing.T) {
		var accepted, requests atomic.Int32
		addr, _ := rawServer(t, func(c net.Conn) {
			accepted.Add(1)
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				req, err := stdhttp.ReadRequest(br)
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				requests.Add(1)
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}
		})
		tr := h1Transport(t, "")
		ctx := context.Background()
		for range 2 {
			if err := tr.Preconnect(ctx, "http://"+addr+"/"); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(50 * time.Millisecond)
		if n := accepted.Load(); n != 1 {
			t.Fatalf("%d connections opened by two preconnects, want 1", n)
		}
		if n := requests.Load(); n != 0 {
			t.Fatalf("the server read %d requests from a preconnect", n)
		}
		if _, err := tr.Do(ctx, &Request{URL: "http://" + addr + "/"}); err != nil {
			t.Fatal(err)
		}
		if n := accepted.Load(); n != 1 {
			t.Fatalf("the request opened a connection of its own (%d in all)", n)
		}
	})
}

// A host the transport has not seen is raced over HTTP/3 and HTTP/2, as for a
// request, and the winner is remembered.
func TestPreconnectToANewHostRemembersItsProtocol(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS() // TCP only: HTTP/3 never connects
	t.Cleanup(srv.Close)
	tr := autoTransport(t, "chrome-146")
	if err := tr.Preconnect(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if p, ok := cachedProtocol(tr, extractHost(srv.URL)); !ok || p != ProtocolHTTP2 {
		t.Fatalf("host cached as (%v, %v), want HTTP/2", p, ok)
	}
}

// A preconnect that cannot connect says why.
func TestPreconnectReportsAFailedConnection(t *testing.T) {
	tr := autoTransport(t, "firefox-148")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := tr.Preconnect(context.Background(), "https://"+addr+"/"); err == nil {
		t.Fatal("a preconnect to a closed port succeeded")
	}
}
