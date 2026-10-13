package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// Concurrent HTTP/2 requests to one host share a single dial. The requests
// that joined it waited in singleflight's Do, which takes no context, so a
// request whose own deadline was short, or which was cancelled, stayed blocked
// until the leader's dial finished or hit the leader's deadline. Against a host
// that stalls the handshake, that is the leader's whole timeout.
func TestHTTP2DialWaiterHonoursItsOwnContext(t *testing.T) {
	// Accepts TCP and never answers the ClientHello.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})

	tr := NewHTTP2Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	key := net.JoinHostPort(host, port)

	leaderCtx, cancelLeader := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelLeader()
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		tr.getOrCreateConn(leaderCtx, host, port, key)
	}()
	time.Sleep(200 * time.Millisecond) // let the leader own the dial

	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancelWaiter()
	start := time.Now()
	_, err = tr.getOrCreateConn(waiterCtx, host, port, key)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter returned %v, want its own deadline", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("waiter returned after %v; it waited on the leader's dial, not its own 300ms deadline", elapsed)
	}

	// The leader still gets its own answer when its deadline arrives.
	cancelLeader()
	select {
	case <-leaderDone:
	case <-time.After(10 * time.Second):
		t.Fatal("leader did not return after its context ended")
	}
}
