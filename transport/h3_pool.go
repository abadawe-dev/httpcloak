package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/http/httptrace"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	tls "github.com/sardanioss/utls"
	"golang.org/x/net/http/httpguts"
)

// h3Pool holds an HTTP3Transport's connections, one per origin (host:port).
//
// It replaces http3.Transport's own pool, which the transport used to send
// through, for what that pool could not do:
//
//   - A connection whose handshake never completes. A dial that resumes a
//     session whose ticket allows early data returns before the handshake is
//     done (DialEarly), and a request then waits for the handshake on nothing
//     but its own context: when the path is black-holed, the connection dies of
//     its handshake timeout and the request waits out its whole deadline. Worse,
//     http3.Transport keeps the dead connection pooled, since a request that
//     ends on its context never evicts it, so every later request to the origin
//     waited out its deadline too until the transport was rebuilt. Here a
//     request waits for the handshake or the connection's end, whichever comes
//     first, and a dead connection is never handed out.
//   - Ending one origin's connection, or setting a silent one aside, without
//     closing every other origin's (http3.Transport has no way to drop one
//     client, so a stalled request used to rebuild the whole transport and cut
//     off every request in flight on any host).
//   - A connection opened ahead of the request that will use it (Preconnect,
//     and auto mode's connect race, whose probe used to open a QUIC connection,
//     close it with a "connect probe" reason, and have the request open
//     another).
//   - Telling whether a failed request was written at all, which is what the
//     caller needs to know to send it again safely.
//
// What goes on the wire is unchanged: connections are dialed by the same dial
// function with the same TLS and QUIC configuration, and each one's HTTP/3
// layer is the http3.Transport's (NewClientConn: the same SETTINGS, QPACK
// streams and request writer it builds for its own pool).
type h3Pool struct {
	// h3 holds the settings each connection's HTTP/3 layer is built with, and
	// the dial function; its own pool is never used.
	h3 *http3.Transport

	mu     sync.Mutex
	conns  map[string]*h3Conn
	closed bool
}

// h3Conn is one origin's connection: being dialed, or dialed.
type h3Conn struct {
	dialed chan struct{} // closed when the dial has ended; conn, cc and err are set by then
	cancel context.CancelFunc
	conn   *quic.Conn
	cc     *http3.ClientConn
	err    error
}

func newH3Pool(h3 *http3.Transport) *h3Pool {
	return &h3Pool{h3: h3, conns: make(map[string]*h3Conn)}
}

// errH3PoolClosed answers a request sent after the transport was closed or
// refreshed under it. Nothing of it was sent.
var errH3PoolClosed = errors.New("http3: transport closed")

func (c *h3Conn) settled() bool {
	select {
	case <-c.dialed:
		return true
	default:
		return false
	}
}

// usable reports whether a settled connection can take a new request.
func (c *h3Conn) usable() bool {
	return c.err == nil && c.conn.Context().Err() == nil
}

// get returns origin's connection, dialing one when there is none or the one
// there has ended. Concurrent callers share one dial. The dial is not cut short
// when the caller that started it gives up: it runs on until the deadline of
// that caller's context, for whoever else is waiting on it and for the request
// after.
func (p *h3Pool) get(ctx context.Context, origin string) (*h3Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errH3PoolClosed
	}
	c := p.conns[origin]
	if c != nil && c.settled() && !c.usable() {
		delete(p.conns, origin)
		c = nil
	}
	if c == nil {
		dialCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		if deadline, ok := ctx.Deadline(); ok {
			var cancelDeadline context.CancelFunc
			dialCtx, cancelDeadline = context.WithDeadline(dialCtx, deadline)
			cancelDial := cancel
			cancel = func() { cancelDeadline(); cancelDial() }
		}
		c = &h3Conn{dialed: make(chan struct{}), cancel: cancel}
		p.conns[origin] = c
		go p.dial(dialCtx, origin, c)
	}
	p.mu.Unlock()

	select {
	case <-c.dialed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.err != nil {
		return nil, c.err
	}
	return c, nil
}

// dial opens origin's connection as http3.Transport.dial would: SNI from the
// origin unless the TLS config names a server, ALPN h3, and the connection's
// HTTP/3 layer from NewClientConn.
func (p *h3Pool) dial(ctx context.Context, origin string, c *h3Conn) {
	defer close(c.dialed)
	defer c.cancel()

	tlsConf := &tls.Config{}
	if p.h3.TLSClientConfig != nil {
		tlsConf = p.h3.TLSClientConfig.Clone()
	}
	if tlsConf.ServerName == "" {
		sni, _, err := net.SplitHostPort(origin)
		if err != nil {
			sni = origin
		}
		tlsConf.ServerName = sni
	}
	tlsConf.NextProtos = []string{http3.NextProtoH3}

	conn, err := p.h3.Dial(ctx, origin, tlsConf, p.h3.QUICConfig)
	if err != nil {
		c.err = err
		p.forget(origin, c)
		return
	}
	cc := p.h3.NewClientConn(conn)

	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		conn.CloseWithError(0, "")
		c.err = errH3PoolClosed
		return
	}
	c.conn, c.cc = conn, cc
}

// forget removes c from the pool, if it is still origin's connection, and
// leaves it open: the requests already on it carry on and get their answers,
// and it ends on its own once they are done and it idles out. It is for a
// connection that should take no new request.
func (p *h3Pool) forget(origin string, c *h3Conn) {
	p.mu.Lock()
	if p.conns[origin] == c {
		delete(p.conns, origin)
	}
	p.mu.Unlock()
}

// close ends every connection and refuses new ones.
func (p *h3Pool) close() {
	p.mu.Lock()
	p.closed = true
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		c.cancel()
		if c.settled() && c.err == nil {
			c.conn.CloseWithError(0, "")
		}
	}
}

// h3MaxRetries is how many times a request that was not written is sent again
// on another connection, so it goes out at most h3MaxRetries+1 times. It is
// Chrome's kMaxRetryAttempts, as for HTTP/2 (maxHTTP2Retries).
const h3MaxRetries = 2

// send sends req on origin's connection.
//
// A request goes again on another connection only when that cannot have it
// acted on twice: when nothing of it was written to the connection it was on
// and that connection had worked (it completed its handshake and then ended,
// had its early data rejected, or said GOAWAY), or when the server rejected it
// unprocessed (H3_REQUEST_REJECTED). One whose connection died before its
// handshake completed is not sent again: the path to the origin is not
// carrying QUIC, and that is the caller's to decide on (auto mode sends it
// over HTTP/2). Its error then says it was not sent (h3PathError).
func (t *HTTP3Transport) send(pool *h3Pool, req *http.Request) (*http.Response, error) {
	if err := validateH3Request(req); err != nil {
		closeRequestBody(req)
		return nil, err
	}
	ctx := req.Context()
	origin := originKey(req.URL)
	watch := h3WatchFrom(ctx)

	for attempt := 0; ; attempt++ {
		c, err := pool.get(ctx, origin)
		if err != nil {
			closeRequestBody(req)
			if ctx.Err() == nil && isQUICTimeout(err) {
				return nil, &h3PathError{err: err}
			}
			return nil, err
		}
		if err := awaitHandshake(ctx, req.Method, c.conn); err != nil {
			pool.forget(origin, c)
			closeRequestBody(req)
			return nil, err
		}

		var written atomic.Bool
		attemptReq := req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			// Called as the request's HEADERS frame is encoded for its
			// stream, before any of it is written: until then, nothing of
			// the request can have left.
			WroteHeaderField: func(string, []string) { written.Store(true) },
		}))
		if watch != nil {
			watch.attach(c.conn, func() { pool.forget(origin, c) })
		}
		resp, err := c.cc.RoundTrip(attemptReq)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil || attempt == h3MaxRetries {
			closeRequestBody(req)
			return nil, err
		}
		if !written.Load() {
			if is0RTTRejectedError(err) {
				// The ticket that offered early data is spent; the next
				// connection makes a full handshake and gets a new one.
				if t.sessionCache != nil {
					t.sessionCache.Put(hostOnly(origin), nil)
				}
				c.conn.CloseWithError(0, "")
			}
			pool.forget(origin, c)
			continue
		}
		var h3Err *http3.Error
		if errors.As(err, &h3Err) && h3Err.ErrorCode == http3.ErrCodeRequestRejected {
			rewound, rerr := rewindBody(req)
			if rerr != nil {
				closeRequestBody(req)
				return nil, err
			}
			req = rewound
			continue
		}
		if !c.usable() {
			pool.forget(origin, c)
		}
		closeRequestBody(req)
		return nil, err
	}
}

// awaitHandshake waits for conn's handshake to complete, as the HTTP/3 layer
// does before it writes a request (all but the 0-RTT methods), but also stops
// when the connection ends first, which the HTTP/3 layer does not notice.
func awaitHandshake(ctx context.Context, method string, conn *quic.Conn) error {
	if method == http3.MethodGet0RTT || method == http3.MethodHead0RTT {
		return nil
	}
	select {
	case <-conn.HandshakeComplete():
		return nil
	case <-conn.Context().Done():
		select {
		case <-conn.HandshakeComplete():
			// It completed and then ended: the request finds that out when
			// it opens its stream, on a connection that had worked.
			return nil
		default:
		}
		return &h3PathError{err: fmt.Errorf("the QUIC connection ended before its handshake completed: %w", context.Cause(conn.Context()))}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// h3PathError is an HTTP/3 request that failed because the path to its origin
// stopped carrying QUIC: its connection's handshake never completed, the dial
// timed out, or the connection went silent under it (h3Watch). Nothing of the
// request was written unless the error says otherwise (RequestNotSent).
type h3PathError struct{ err error }

func (e *h3PathError) Error() string { return e.err.Error() }
func (e *h3PathError) Unwrap() error { return e.err }

// isH3PathError reports whether err is an h3PathError.
func isH3PathError(err error) bool {
	var pathErr *h3PathError
	return errors.As(err, &pathErr)
}

// isQUICTimeout reports whether err is QUIC giving up on a silent peer: the
// handshake or the connection idled out.
func isQUICTimeout(err error) bool {
	var idle *quic.IdleTimeoutError
	var handshake *quic.HandshakeTimeoutError
	return errors.As(err, &idle) || errors.As(err, &handshake)
}

// validateH3Request refuses what http3.Transport.RoundTripOpt refuses before it
// looks for a connection, which send skips by sending on a ClientConn.
func validateH3Request(req *http.Request) error {
	if req.URL == nil {
		return errors.New("http3: nil Request.URL")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("http3: unsupported protocol scheme: %s", req.URL.Scheme)
	}
	if req.URL.Host == "" {
		return errors.New("http3: no Host in request URL")
	}
	if req.Header == nil {
		return errors.New("http3: nil Request.Header")
	}
	if req.Method != "" && (strings.IndexFunc(req.Method, func(r rune) bool { return !httpguts.IsTokenRune(r) }) != -1) {
		return fmt.Errorf("http3: invalid method %q", req.Method)
	}
	for k, vv := range req.Header {
		if k == http.HeaderOrderKey || k == http.PHeaderOrderKey {
			continue
		}
		if !httpguts.ValidHeaderFieldName(k) {
			return fmt.Errorf("http3: invalid http header field name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return fmt.Errorf("http3: invalid http header field value %q for key %v", v, k)
			}
		}
	}
	return nil
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

// rewindBody returns req with its body from the start, for sending it again.
func rewindBody(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("the request body cannot be sent again")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	rewound := *req
	rewound.Body = body
	return &rewound, nil
}

// h3Watch follows the connection an HTTP/3 request is on, so that its sender
// can tell a path that went silent from a server that is slow to answer.
//
// A live path answers what the request sends: QUIC acknowledges every packet
// that carries data within the peer's max_ack_delay (25 ms by default), so a
// connection that has received no packet at all in the seconds since the
// request was handed to it is not carrying anything, whatever the server is
// doing. One that has received something is alive, and a request on it that
// has no answer yet is waiting on the server, which may be working on it.
type h3Watch struct {
	ready     chan struct{} // closed once the request has a connection
	readyOnce sync.Once

	mu     sync.Mutex
	conn   *quic.Conn
	before uint64 // packets the connection had received when the request got it
	forget func()
}

type h3WatchKey struct{}

func newH3Watch() *h3Watch { return &h3Watch{ready: make(chan struct{})} }

func withH3Watch(ctx context.Context, w *h3Watch) context.Context {
	return context.WithValue(ctx, h3WatchKey{}, w)
}

func h3WatchFrom(ctx context.Context) *h3Watch {
	w, _ := ctx.Value(h3WatchKey{}).(*h3Watch)
	return w
}

// attach records the connection the request is about to be written on, and
// how to take that connection out of the pool.
func (w *h3Watch) attach(conn *quic.Conn, forget func()) {
	w.mu.Lock()
	w.conn = conn
	w.before = conn.ConnectionStats().PacketsReceived
	w.forget = forget
	w.mu.Unlock()
	w.readyOnce.Do(func() { close(w.ready) })
}

// silent reports whether the request's connection has received nothing since
// the request got it, and if so takes it out of the pool, so that no new
// request is sent on it. It is left open: should the path come back, the
// requests on it still get their answers, and it ends by itself otherwise,
// when QUIC's idle timeout runs out.
func (w *h3Watch) silent() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn.ConnectionStats().PacketsReceived != w.before {
		return false
	}
	w.forget()
	return true
}

type ipv4FirstKey struct{}

// withIPv4First asks the dials made for a request under ctx to lead with
// IPv4, for a request sent again after the path its first connection took
// went silent (an IPv6 black hole is the common cause). It is the request's
// alone: other requests' dials, to this origin or any other, are unaffected.
func withIPv4First(ctx context.Context) context.Context {
	return context.WithValue(ctx, ipv4FirstKey{}, true)
}

func ipv4FirstFrom(ctx context.Context) bool {
	v, _ := ctx.Value(ipv4FirstKey{}).(bool)
	return v
}
