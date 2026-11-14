package transport

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
)

// udpGate relays UDP between clients and a server, and can stop carrying
// anything in either direction: a path that black-holes QUIC (a firewall that
// drops UDP, a VPN that came up, a router shedding UDP under load) while the
// server itself is fine.
type udpGate struct {
	front    *net.UDPConn
	server   *net.UDPAddr
	blocked  atomic.Bool
	mu       sync.Mutex
	upstream map[string]*net.UDPConn
	closed   chan struct{}
}

func startUDPGate(t *testing.T, server *net.UDPAddr) *udpGate {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &udpGate{front: front, server: server, upstream: map[string]*net.UDPConn{}, closed: make(chan struct{})}
	go g.run()
	t.Cleanup(g.close)
	return g
}

func (g *udpGate) port() int { return g.front.LocalAddr().(*net.UDPAddr).Port }

func (g *udpGate) run() {
	buf := make([]byte, 65536)
	for {
		n, client, err := g.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if g.blocked.Load() {
			continue
		}
		up := g.upstreamFor(client)
		if up != nil {
			up.Write(buf[:n])
		}
	}
}

func (g *udpGate) upstreamFor(client *net.UDPAddr) *net.UDPConn {
	g.mu.Lock()
	defer g.mu.Unlock()
	if up, ok := g.upstream[client.String()]; ok {
		return up
	}
	up, err := net.DialUDP("udp", nil, g.server)
	if err != nil {
		return nil
	}
	g.upstream[client.String()] = up
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			if g.blocked.Load() {
				continue
			}
			g.front.WriteToUDP(buf[:n], client)
		}
	}()
	return up
}

func (g *udpGate) close() {
	g.front.Close()
	g.mu.Lock()
	for _, up := range g.upstream {
		up.Close()
	}
	g.mu.Unlock()
}

// gatedH3Origin is an HTTP/3 server that allows 0-RTT (so a client that has
// been there resumes with early data, as at a real CDN), reached through a
// udpGate. It returns the gate and the URL that goes through it.
func gatedH3Origin(t *testing.T, handler shttp.HandlerFunc) (*udpGate, string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig:  h3RaceTestTLS(t),
		QUICConfig: &quic.Config{Allow0RTT: true},
		Handler:    handler,
	}
	go func() { _ = srv.Serve(conn) }()
	t.Cleanup(func() { srv.Close(); conn.Close() })
	time.Sleep(100 * time.Millisecond)
	g := startUDPGate(t, conn.LocalAddr().(*net.UDPAddr))
	return g, fmt.Sprintf("https://127.0.0.1:%d/", g.port())
}
