package transport

import (
	"context"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type connKey struct{}

// dropsOnceServer serves HTTP/2 and HTTP/1.1, and logs each request as
// "<proto> <method> <path>". The first request to /drop has its connection
// closed under it once read, before any answer: a load balancer or an edge
// dropping a connection. Every other request is answered.
func dropsOnceServer(t *testing.T) (*httptest.Server, *protoLog) {
	t.Helper()
	log := &protoLog{}
	var once sync.Once
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		proto := "h1"
		if r.ProtoMajor == 2 {
			proto = "h2"
		}
		log.add(proto, r.Method+" "+r.URL.Path)
		dropped := false
		if r.URL.Path == "/drop" {
			once.Do(func() {
				r.Context().Value(connKey{}).(net.Conn).Close()
				dropped = true
			})
		}
		if !dropped {
			w.Write([]byte("ok"))
		}
	}))
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, c)
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, log
}

// A GET whose HTTP/2 connection was lost before its answer may be sent again,
// and was, over HTTP/1.1 on a new connection: to a host that speaks HTTP/2,
// with HTTP/1.1's header order and a TLS connection that offered h2, which
// Chrome never does. Chrome sends it again on a new connection of the same
// protocol (HttpNetworkTransaction::ShouldResendRequest), and so does this now.
func TestAGetWhoseHTTP2ConnectionWasLostGoesAgainOverHTTP2(t *testing.T) {
	cases := []struct {
		name  string
		proxy bool
	}{{"direct", false}, {"through a CONNECT proxy", true}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, log := dropsOnceServer(t)
			var proxy *ProxyConfig
			if c.proxy {
				proxy = &ProxyConfig{URL: connectProxy(t, "")}
			}
			tr := NewTransportWithConfig("chrome-146", proxy, nil)
			tr.SetInsecureSkipVerify(true)
			tr.SetProtocol(ProtocolAuto)
			t.Cleanup(tr.Close)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := tr.Do(ctx, &Request{URL: srv.URL + "/"}); err != nil {
				t.Fatalf("warm-up: %v", err)
			}
			resp, err := tr.Do(ctx, &Request{URL: srv.URL + "/drop"})
			if err != nil {
				t.Fatalf("the GET should have gone again: %v", err)
			}
			if resp.Protocol != "h2" {
				t.Fatalf("answered over %s, want h2", resp.Protocol)
			}
			if n := log.count("h1 GET /drop"); n != 0 {
				t.Fatalf("the GET went again over HTTP/1.1: %q", log.all())
			}
			if n := log.count("h2 GET /drop"); n != 2 {
				t.Fatalf("server read the GET over HTTP/2 %d times, want twice: %q", n, log.all())
			}
		})
	}
}

// An HTTP/2 connection in use carries on however old it is, as Chrome's does
// (its SPDY sessions have no maximum age). It was retired at five minutes old,
// so the request after paid a new handshake, and a proxy's CONNECT, in the
// middle of whatever the connection was busy with.
func TestABusyHTTP2ConnectionIsKeptPastFiveMinutes(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Write([]byte("ok"))
	}))
	l := &countingListener{Listener: srv.Listener}
	srv.Listener = l
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tr := autoTransport(t, "firefox-148")

	ctx := context.Background()
	if _, err := tr.Do(ctx, &Request{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	h2 := tr.GetHTTP2Transport()
	h2.connsMu.RLock()
	for _, conn := range h2.conns {
		conn.mu.Lock()
		conn.createdAt = conn.createdAt.Add(-6 * time.Minute) // opened six minutes ago, used just now
		conn.mu.Unlock()
	}
	h2.connsMu.RUnlock()

	if _, err := tr.Do(ctx, &Request{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if n := l.accepted.Load(); n != 1 {
		t.Fatalf("%d connections: the six-minute-old connection was replaced", n)
	}
}
