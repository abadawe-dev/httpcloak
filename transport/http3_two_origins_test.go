package transport

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go/http3"
)

// startH3Origin serves HTTP/3 on a fresh loopback port.
func startH3Origin(t *testing.T, handler shttp.HandlerFunc) (url string) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{TLSConfig: h3RaceTestTLS(t), Handler: handler}
	go func() { _ = srv.Serve(c) }()
	t.Cleanup(func() { srv.Close(); c.Close() })
	time.Sleep(100 * time.Millisecond)
	return fmt.Sprintf("https://127.0.0.1:%d/", c.LocalAddr().(*net.UDPAddr).Port)
}

func h3Fetch(tr *HTTP3Transport, url string) error {
	req, err := shttp.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// Issue #126. Chrome's QUIC connections use zero-length connection IDs, so a
// server's packets carry nothing that says which connection they belong to.
// Every direct connection in a transport shared one UDP socket, and quic-go
// demultiplexes a socket by connection ID, so with two origins open at once
// one origin's packets went to the other's connection. Chromium opens a UDP
// socket per QUIC session.
func TestHTTP3TwoOriginsOnOneTransport(t *testing.T) {
	handler := shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	})
	a := startH3Origin(t, handler)
	b := startH3Origin(t, handler)

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	var failed atomic.Int32
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 20; i++ {
		url := a
		if i%2 == 1 {
			url = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h3Fetch(tr, url); err != nil {
				failed.Add(1)
				t.Logf("%s: %v", url, err)
			}
		}()
	}
	wg.Wait()
	if n := failed.Load(); n != 0 {
		t.Errorf("%d of 20 concurrent requests across two origins failed (%v)", n, time.Since(start).Round(time.Millisecond))
	}

	// Sequential revisits must not stall either.
	for _, url := range []string{a, b, a, b} {
		s := time.Now()
		if err := h3Fetch(tr, url); err != nil {
			t.Errorf("sequential %s: %v", url, err)
		}
		if d := time.Since(s); d > 2*time.Second {
			t.Errorf("sequential %s took %v", url, d.Round(time.Millisecond))
		}
	}
}

func (t *HTTP3Transport) liveSockets() int {
	t.liveMu.Lock()
	defer t.liveMu.Unlock()
	return len(t.sockets)
}

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(ents)
}

// Each connection has its own socket, so connections to two origins leave
// from two source ports, as a browser's do; they used to share one. Each
// socket is closed with its connection, and Refresh and Close end them all.
func TestHTTP3SocketPerConnection(t *testing.T) {
	var mu sync.Mutex
	ports := map[string]bool{}
	handler := shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		mu.Lock()
		ports[r.RemoteAddr] = true
		mu.Unlock()
		w.WriteHeader(200)
	})
	a := startH3Origin(t, handler)
	b := startH3Origin(t, handler)

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()
	if n := tr.liveSockets(); n != 0 {
		t.Fatalf("%d sockets before any dial; a transport that never dials should hold none", n)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		for _, u := range []string{a, b} {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				if err := h3Fetch(tr, u); err != nil {
					t.Errorf("%s: %v", u, err)
				}
			}(u)
		}
	}
	wg.Wait()
	mu.Lock()
	if len(ports) != 2 {
		t.Errorf("connections to two origins arrived from %d source address(es): %v", len(ports), ports)
	}
	mu.Unlock()
	if n := tr.liveSockets(); n != 2 {
		t.Errorf("%d live sockets with two origins open, want 2", n)
	}

	if err := tr.Refresh(); err != nil {
		t.Fatal(err)
	}
	if n := tr.liveSockets(); n != 0 {
		t.Errorf("%d live sockets after Refresh, want 0", n)
	}
	if err := h3Fetch(tr, a); err != nil {
		t.Fatalf("after Refresh: %v", err)
	}
	tr.Close()
	if n := tr.liveSockets(); n != 0 {
		t.Errorf("%d live sockets after Close, want 0", n)
	}
	if err := h3Fetch(tr, a); err == nil {
		t.Error("a request after Close succeeded")
	}
}

// Every transport that dialed HTTP/3 used to keep its socket after Close,
// because quic.Transport.Close only closes a socket it created and this one
// was handed in. Only the garbage collector's finalizer on the socket ever
// closed it, so anything still holding the transport, such as a long-lived
// session after Refresh or Close, held the descriptor too. The transports are
// kept reachable here so the finalizer cannot hide that.
func TestHTTP3CloseReleasesSockets(t *testing.T) {
	a := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) { w.WriteHeader(200) }))
	// One warm-up so lazily created process-wide descriptors are not counted.
	warm, _ := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
	warm.SetInsecureSkipVerify(true)
	h3Fetch(warm, a)
	warm.Close()
	time.Sleep(200 * time.Millisecond)

	before := openFDs(t)
	var keep []*HTTP3Transport
	for i := 0; i < 20; i++ {
		tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
		if err != nil {
			t.Fatal(err)
		}
		tr.SetInsecureSkipVerify(true)
		if err := h3Fetch(tr, a); err != nil {
			t.Fatal(err)
		}
		tr.Close()
		keep = append(keep, tr)
	}
	time.Sleep(300 * time.Millisecond)
	if after := openFDs(t); after > before+2 {
		t.Errorf("open descriptors went from %d to %d over 20 dial-and-Close cycles", before, after)
	}
	runtime.KeepAlive(keep)
}

// A dial racing Close must not leave a socket behind: the socket is registered
// under the same lock Close takes, and a dial that loses the race closes its
// own.
func TestHTTP3DialRacingCloseLeavesNoSocket(t *testing.T) {
	a := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) { w.WriteHeader(200) }))
	before := openFDs(t)
	for i := 0; i < 10; i++ {
		tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
		if err != nil {
			t.Fatal(err)
		}
		tr.SetInsecureSkipVerify(true)
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() { defer wg.Done(); h3Fetch(tr, a) }()
		}
		time.Sleep(time.Duration(i) * time.Millisecond)
		tr.Close()
		wg.Wait()
		if n := tr.liveSockets(); n != 0 {
			t.Errorf("round %d: %d sockets registered after Close", i, n)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if after := openFDs(t); after > before+2 {
		t.Errorf("open descriptors went from %d to %d", before, after)
	}
}
