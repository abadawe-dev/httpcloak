package transport

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	stdtls "crypto/tls"

	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// Wire locks on the parent stream and exclusive flag a HEADERS frame carries.
//
// Chromium builds a dependency chain (net/spdy/http2_priority_dependencies.cc):
// a new stream depends exclusively on the newest stream still open at the same
// or the nearest higher priority. Against this kind of server, holding every
// response open, Chrome 147 and 155 named that parent on every stream of five
// page loads. We used to name stream 0 on every HEADERS frame, which no
// Chromium build does once two streams overlap on a connection.
//
// Firefox (133, 148 and 152 captured) names stream 0 and never sets exclusive,
// so its presets must not grow a chain.

type depCapture struct {
	stream uint32
	path   string
	weight int
	dep    uint32
	excl   bool
}

// depServer answers nothing until told to: every stream stays open until the
// test releases its path, so the client's view of which streams are open is
// fully under the test's control. A path containing "refuse" is answered with
// RST_STREAM(REFUSED_STREAM) on its first arrival.
type depServer struct {
	addr string

	mu       sync.Mutex
	caps     []depCapture
	arrived  *sync.Cond
	release  map[string]chan struct{}
	refused  map[string]bool
	conns    int
	ln       net.Listener
	tlsCfg   *stdtls.Config
	closedCh chan struct{}
}

func startDepServer(t *testing.T) *depServer {
	t.Helper()
	base := startH2CaptureServer(t) // for its certificate only
	base.listener.Close()
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", base.tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	s := &depServer{addr: ln.Addr().String(), release: map[string]chan struct{}{}, refused: map[string]bool{}, ln: ln, closedCh: make(chan struct{})}
	s.arrived = sync.NewCond(&s.mu)
	t.Cleanup(func() {
		close(s.closedCh)
		ln.Close()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			go s.serve(c.(*stdtls.Conn))
		}
	}()
	return s
}

func (s *depServer) gate(path string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.release[path]
	if !ok {
		ch = make(chan struct{})
		s.release[path] = ch
	}
	return ch
}

func (s *depServer) open(path string) { close(s.gate(path)) }

func (s *depServer) serve(c *stdtls.Conn) {
	defer c.Close()
	if c.Handshake() != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, len(h2PrefaceStr))); err != nil {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var wmu sync.Mutex
	write := func(f func()) { wmu.Lock(); f(); wmu.Unlock() }
	write(func() { fr.WriteSettings() })
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				write(func() { fr.WriteSettingsAck() })
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				write(func() { fr.WritePing(true, f.Data) })
			}
		case *http2.MetaHeadersFrame:
			path := ""
			for _, hf := range f.Fields {
				if hf.Name == ":path" {
					path = hf.Value
				}
			}
			id := f.StreamID
			s.mu.Lock()
			s.caps = append(s.caps, depCapture{id, path, int(f.Priority.Weight) + 1, f.Priority.StreamDep, f.Priority.Exclusive})
			refuse := strings.Contains(path, "refuse") && !s.refused[path]
			if refuse {
				s.refused[path] = true
			}
			s.arrived.Broadcast()
			s.mu.Unlock()
			if refuse {
				write(func() { fr.WriteRSTStream(id, http2.ErrCodeRefusedStream) })
				continue
			}
			gate := s.gate(path)
			go func() {
				select {
				case <-gate:
				case <-s.closedCh:
					return
				}
				var b strings.Builder
				e := hpack.NewEncoder(&b)
				e.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				write(func() {
					fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte(b.String()), EndHeaders: true, EndStream: true})
				})
			}()
		}
	}
}

// waitFor blocks until n HEADERS frames have arrived.
func (s *depServer) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.AfterFunc(5*time.Second, func() { s.mu.Lock(); s.arrived.Broadcast(); s.mu.Unlock() })
	defer deadline.Stop()
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.caps) < n {
		if time.Since(start) > 5*time.Second {
			t.Fatalf("only %d of %d HEADERS arrived: %+v", len(s.caps), n, s.caps)
		}
		s.arrived.Wait()
	}
}

func (s *depServer) byPath(path string) []depCapture {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []depCapture
	for _, c := range s.caps {
		if c.path == path {
			out = append(out, c)
		}
	}
	return out
}

type depClient struct {
	t   *testing.T
	tr  *Transport
	s   *depServer
	wg  sync.WaitGroup
	n   int
	ctx context.Context
}

func newDepClient(t *testing.T, preset string, s *depServer) *depClient {
	tr := NewTransport(preset)
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return &depClient{t: t, tr: tr, s: s, ctx: ctx}
}

// send starts a request and waits until its HEADERS (all of them, for a
// refused request that is retried) reach the server, so the next one is
// opened strictly after it.
func (c *depClient) send(path, dest string, arrivals int) {
	c.n += arrivals
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		resp, err := c.tr.Do(c.ctx, &Request{Method: "GET", URL: "https://" + c.s.addr + path,
			Headers: map[string][]string{"Sec-Fetch-Dest": {dest}}})
		if err != nil {
			c.t.Errorf("%s: %v", path, err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	c.s.waitFor(c.t, c.n)
}

func (c *depClient) finish(path string) {
	c.s.open(path)
	// Let the response land so the client sees the stream close.
	time.Sleep(150 * time.Millisecond)
}

func (c *depClient) expect(path string, wantDep uint32, wantWeight int, wantExcl bool) {
	c.t.Helper()
	caps := c.s.byPath(path)
	if len(caps) == 0 {
		c.t.Errorf("%s never arrived", path)
		return
	}
	got := caps[len(caps)-1]
	if got.dep != wantDep || got.weight != wantWeight || got.excl != wantExcl {
		c.t.Errorf("%s (stream %d): dep %d weight %d exclusive %v, want dep %d weight %d exclusive %v",
			path, got.stream, got.dep, got.weight, got.excl, wantDep, wantWeight, wantExcl)
	}
}

func (c *depClient) done() {
	for _, p := range []string{"/doc", "/script", "/img1", "/img2", "/style", "/fetch", "/late", "/img-refuse", "/after"} {
		select {
		case <-c.s.gate(p):
		default:
			c.s.open(p)
		}
	}
	c.wg.Wait()
	if n := c.s.conns; n != 1 {
		c.t.Errorf("requests spread over %d connections; the chain is per connection", n)
	}
}

func TestChromiumStreamDependencyChain(t *testing.T) {
	s := startDepServer(t)
	c := newDepClient(t, "chrome-155-windows", s)

	c.send("/doc", "document", 1)  // stream 1, u=0
	c.send("/script", "script", 1) // stream 3, u=1
	c.send("/img1", "image", 1)    // stream 5, u=2
	c.send("/img2", "image", 1)    // stream 7, u=2
	c.send("/style", "style", 1)   // stream 9, u=0
	c.send("/fetch", "empty", 1)   // stream 11, u=1

	c.expect("/doc", 0, 256, true)    // nothing open
	c.expect("/script", 1, 220, true) // no u=1 yet, so the newest u=0
	c.expect("/img1", 3, 183, true)   // no u=2 yet, so the newest u=1
	c.expect("/img2", 5, 183, true)   // the newest u=2
	c.expect("/style", 1, 256, true)  // the newest u=0
	c.expect("/fetch", 3, 220, true)  // the newest u=1

	// A finished stream leaves the chain: with /script and /fetch done there
	// is no u=1 left, so the next u=1 hangs off the newest u=0, /style.
	c.finish("/script")
	c.finish("/fetch")
	c.send("/late", "empty", 1)
	c.expect("/late", 9, 220, true)
	c.done()
}

// A refused stream is closed the moment the RST_STREAM arrives, as Chromium
// destroys it, so the retry that follows cannot name it as its parent. Without
// that, the retry depended on a stream the server had already closed.
func TestRefusedStreamLeavesTheChainBeforeTheRetry(t *testing.T) {
	s := startDepServer(t)
	c := newDepClient(t, "chrome-155-windows", s)

	c.send("/doc", "document", 1)     // stream 1, u=0
	c.send("/img-refuse", "image", 2) // stream 3 refused, retried as stream 5
	caps := s.byPath("/img-refuse")
	if len(caps) != 2 {
		t.Fatalf("got %d arrivals for the refused request, want 2", len(caps))
	}
	if caps[1].dep != 1 {
		t.Errorf("retry (stream %d) depends on %d, want 1; stream %d was refused and is gone",
			caps[1].stream, caps[1].dep, caps[0].stream)
	}
	c.send("/after", "image", 1)
	c.expect("/after", caps[1].stream, 183, true)
	c.done()
}

func TestFirefoxStreamsHaveNoDependencies(t *testing.T) {
	s := startDepServer(t)
	c := newDepClient(t, "firefox-148-windows", s)

	c.send("/doc", "document", 1)
	c.send("/script", "script", 1)
	c.send("/img1", "image", 1)
	c.send("/style", "style", 1)
	c.send("/fetch", "empty", 1)

	c.expect("/doc", 0, 42, false)
	c.expect("/script", 0, 22, false)
	c.expect("/img1", 0, 12, false)
	c.expect("/style", 0, 22, false)
	c.expect("/fetch", 0, 22, false)
	c.done()
}
