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

// The protocol-racing entrypoint owns a dial too, even without a request
// waiting in getOrCreateConn. All simultaneous Close callers join its shutdown.
func TestHTTP2ConcurrentCloseJoinsConnectProbe(t *testing.T) {
	addr, started, closed := pendingCONNECT(t)
	tr := NewHTTP2TransportWithProxy(fingerprint.Get("chrome-146"), dns.NewCache(), &ProxyConfig{URL: "http://" + addr})
	t.Cleanup(tr.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request := make(chan error, 1)
	go func() { request <- tr.Connect(ctx, "example.com", "443") }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not reach the proxy")
	}
	shutdown := make(chan struct{}, 8)
	for range cap(shutdown) {
		go func() { tr.Close(); shutdown <- struct{}{} }()
	}
	for range cap(shutdown) {
		select {
		case <-shutdown:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Close did not join the probe")
		}
	}
	select {
	case err := <-request:
		if err == nil {
			t.Fatal("closed transport returned a successful probe")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect survived Close")
	}
	select {
	case err := <-closed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("proxy connection ended with %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe socket survived Close")
	}
}

// An ALPN result has completed its handshake, but remains an owned socket
// until its intended consumer takes it. Close must wait for its disposal,
// including the interval between singleflight completion and leader delivery.
func TestHTTP2CloseJoinsUnclaimedALPNResult(t *testing.T) {
	closed := make(chan struct{})
	var observed sync.Once
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateClosed {
			observed.Do(func() { close(closed) })
		}
	}
	srv.StartTLS() // HTTP/1.1 ALPN, so the result carries a live TLS connection.
	t.Cleanup(srv.Close)
	tr := NewHTTP2Transport(fingerprint.Get("chrome-146"), dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := tr.dialConnection(ctx, host, port, u.Host, 1)
	var alpn *ALPNMismatchError
	if !errors.As(err, &alpn) || alpn.TLSConn == nil {
		tr.finishDial(result.pending)
		t.Fatalf("want live ALPN result, got %v", err)
	}
	// Always release the registration before cleanup, even if an assertion fails.
	defer func() { tr.finishDial(result.pending) }()
	defer func() { closeALPN(err) }()
	shutdown := make(chan struct{})
	go func() { tr.Close(); close(shutdown) }()
	// Observe shutdown's state transition before allowing the consumer to
	// accept the result. The handshake is already complete.
	for {
		tr.connsMu.RLock()
		stopping := tr.closed
		tr.connsMu.RUnlock()
		if stopping {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("shutdown did not start")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-shutdown:
		t.Fatal("Close returned before the unclaimed ALPN result was disposed")
	default:
	}
	if conn, rejected := tr.acceptDial(ctx, result, err); conn != nil || rejected == nil || errors.As(rejected, &alpn) {
		t.Fatalf("shutdown transferred a live ALPN result: conn=%v err=%v", conn, rejected)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("rejecting the unclaimed result did not close its socket")
	}
	// The socket has been disposed; now completion may release Close.
	err = nil
	tr.finishDial(result.pending)
	result.pending = nil
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after the ALPN result was disposed")
	}
}

// Done is evaluated by getOrCreateConn's select only after it has joined the
// singleflight slot. This makes the coalesced-waiter case deterministic without
// sleeping or inspecting singleflight's private state.
type dialWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *dialWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestHTTP2CloseJoinsCoalescedWaitersDedicatedALPNRetry(t *testing.T) {
	first, second := make(chan struct{}), make(chan struct{})
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	var firstReleased, secondReleased sync.Once
	defer firstReleased.Do(func() { close(releaseFirst) })
	defer secondReleased.Do(func() { close(releaseSecond) })
	var handshakes atomic.Int32
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		switch handshakes.Add(1) {
		case 1:
			close(first)
			<-releaseFirst
		case 2:
			close(second)
			<-releaseSecond
		}
		return nil, nil
	}}
	srv.StartTLS() // HTTP/1.1 only.
	t.Cleanup(srv.Close)
	tr := NewHTTP2Transport(fingerprint.Get("chrome-146"), dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leader := make(chan error, 1)
	go func() {
		_, err := tr.getOrCreateConn(ctx, host, port, u.Host)
		leader <- err
	}()
	select {
	case <-first:
	case <-time.After(3 * time.Second):
		t.Fatal("shared handshake did not start")
	}
	waiting := &dialWaitingContext{Context: ctx, waiting: make(chan struct{})}
	waiter := make(chan error, 1)
	go func() {
		_, err := tr.getOrCreateConn(waiting, host, port, u.Host)
		waiter <- err
	}()
	select {
	case <-waiting.waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("second caller did not join the shared dial")
	}
	firstReleased.Do(func() { close(releaseFirst) })
	select {
	case err := <-leader:
		var alpn *ALPNMismatchError
		if !errors.As(err, &alpn) || alpn.TLSConn == nil {
			t.Fatalf("leader did not receive its own ALPN socket: %v", err)
		}
		closeALPN(err)
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not receive the ALPN result")
	}
	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Fatal("coalesced caller did not start its dedicated replacement")
	}
	shutdown := make(chan struct{})
	go func() { tr.Close(); close(shutdown) }()
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel and join the dedicated ALPN replacement")
	}
	select {
	case err := <-waiter:
		var alpn *ALPNMismatchError
		if err == nil || errors.As(err, &alpn) {
			closeALPN(err)
			t.Fatalf("closed transport handed the waiter a live connection: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dedicated ALPN replacement survived Close")
	}
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("performed %d handshakes, want one shared and one dedicated", got)
	}
}
