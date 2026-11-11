package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// pendingCONNECT accepts a real proxy request and leaves it unanswered.
func pendingCONNECT(t *testing.T) (string, <-chan struct{}, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	started := make(chan struct{})
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := stdhttp.ReadRequest(reader)
		if err != nil {
			closed <- err
			return
		}
		request.Body.Close()
		t.Cleanup(func() { conn.Close() })
		close(started)
		// CONNECT is deliberately never answered. Its request deadline is far
		// away, so only owning-transport shutdown can close it promptly.
		_, err = reader.ReadByte()
		closed <- err
	}()

	return listener.Addr().String(), started, closed
}

// A request may stop waiting on a shared dial, but the session that owns that
// dial must not leave its socket behind when the session itself closes.
func TestHTTP2CloseJoinsPendingProxyConnect(t *testing.T) {
	addr, started, closed := pendingCONNECT(t)

	tr := NewHTTP2TransportWithProxy(fingerprint.Get("chrome-146"), dns.NewCache(), &ProxyConfig{URL: "http://" + addr})
	t.Cleanup(tr.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request := make(chan error, 1)
	go func() {
		_, err := tr.getOrCreateConn(ctx, "example.com", "443", "example.com:443")
		request <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("shared dial did not reach the loopback proxy")
	}
	cancel()
	select {
	case err := <-request:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the triggering request returned %v, want cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the triggering request did not stop waiting on its shared dial")
	}
	shutdown := make(chan struct{})
	go func() { tr.Close(); close(shutdown) }()
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel and join its pending shared dial")
	}
	select {
	case err := <-closed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("proxy connection ended with %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the pending CONNECT socket survived transport Close")
	}
}

// Native SDK calls use HTTP/1.1; cancellation must interrupt CONNECT before
// the normal HTTP exchange's context watcher has been installed.
func TestHTTP1RequestCancellationInterruptsPendingConnect(t *testing.T) {
	addr, started, closed := pendingCONNECT(t)
	tr := NewTransportWithConfig("chrome-146", &ProxyConfig{URL: "http://" + addr}, nil)
	tr.SetProtocol(ProtocolHTTP1)
	t.Cleanup(tr.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request := make(chan error, 1)
	go func() {
		_, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://example.com/"})
		request <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the loopback proxy")
	}
	cancel()
	select {
	case err := <-request:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("request returned %v, want cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the HTTP/1.1 request did not interrupt CONNECT")
	}
	select {
	case err := <-closed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("proxy connection ended with %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled CONNECT socket remained open")
	}
}

// A request's cancellation is not transport shutdown: the other waiter must
// still receive the shared connection, which remains reusable afterwards.
func TestHTTP2CancelledDialLeaderPreservesOtherWaitersAndReuse(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var observed, released sync.Once
	var handshakes atomic.Int32
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		handshakes.Add(1)
		observed.Do(func() { close(started) })
		<-release
		return nil, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	t.Cleanup(func() { released.Do(func() { close(release) }) })
	tr := NewHTTP2Transport(fingerprint.Get("chrome-146"), dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	leaderCtx, cancelLeader := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelLeader()
	leader := make(chan error, 1)
	go func() {
		_, err := tr.getOrCreateConn(leaderCtx, host, port, u.Host)
		leader <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("the shared TLS handshake did not start")
	}
	type result struct {
		conn *persistentConn
		err  error
	}
	waiting := make(chan struct{})
	waiter := make(chan result, 1)
	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWaiter()
	go func() {
		close(waiting)
		conn, err := tr.getOrCreateConn(waiterCtx, host, port, u.Host)
		waiter <- result{conn, err}
	}()
	<-waiting
	cancelLeader()
	select {
	case err := <-leader:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader returned %v, want cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not stop waiting on cancellation")
	}
	released.Do(func() { close(release) })
	var obtained *persistentConn
	select {
	case result := <-waiter:
		if result.err != nil {
			t.Fatalf("cancelling another waiter stopped the shared handshake: %v", result.err)
		}
		obtained = result.conn
	case <-time.After(3 * time.Second):
		t.Fatal("the other waiter did not receive its connection")
	}
	reused, err := tr.getOrCreateConn(waiterCtx, host, port, u.Host)
	if err != nil || reused != obtained || handshakes.Load() != 1 {
		t.Fatalf("shared connection was not reused: err=%v, same=%v, handshakes=%d", err, reused == obtained, handshakes.Load())
	}
}
