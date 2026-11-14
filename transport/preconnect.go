package transport

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	utls "github.com/sardanioss/utls"
)

// Preconnect opens the connection a request to rawURL would be sent on, and
// sends no request: DNS, then TCP and TLS (through the proxy's CONNECT when
// there is one) or QUIC, on the protocol a request would take. When that
// connection is open already it does nothing. The connection then waits in
// the pool for the request, which goes out on it without a handshake.
//
// It is what Chrome does for <link rel=preconnect> and for the hosts it
// predicts a navigation will need: a connection, nothing the server sees as a
// request. A caller that knows it is about to send requests to a host (the
// moment stock appears, say) opens the connections in parallel, ahead of them.
//
// It is bounded by the transport's timeout, or ctx's deadline when sooner. A
// host auto mode has not seen before is raced over HTTP/3 and HTTP/2 as for a
// request, and the winner remembered; HTTP/3 broken for a host is honoured.
// An HTTP/1.1 connection waits among the host's idle ones, for as long as an
// idle connection is kept (90 s).
func (t *Transport) Preconnect(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return NewRequestError("parse_url", "", "", "", err)
	}
	if err := checkScheme(u); err != nil {
		return err
	}
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}

	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	snap := t.snapshot()
	if snap.tcpProxyError != nil && !(snap.protocol == ProtocolHTTP3 || snap.protocol == ProtocolAuto) {
		return snap.tcpProxyError
	}
	if u.Scheme == "http" {
		if snap.tcpProxyError != nil {
			return snap.tcpProxyError
		}
		return t.h1Transport.Preconnect(ctx, host, port, u.Scheme)
	}

	h1 := func() error { return t.h1Transport.Preconnect(ctx, host, port, u.Scheme) }
	h3 := func() error {
		if snap.h3 == nil {
			return errHTTP3Disabled(host, port)
		}
		return snap.h3.Connect(ctx, host, port)
	}
	switch snap.protocol {
	case ProtocolHTTP1:
		return h1()
	case ProtocolHTTP2:
		return t.preconnectHTTP2(ctx, host, port, false)
	case ProtocolHTTP3:
		if snap.h3ProxyError != nil {
			return snap.h3ProxyError
		}
		return h3()
	}

	// Auto, as Do and doAuto choose.
	proxied := snap.proxy != nil && (snap.proxy.URL != "" || snap.proxy.TCPProxy != "" || snap.proxy.UDPProxy != "")
	if proxied {
		udpProxy := snap.proxy.UDPProxy
		if udpProxy == "" {
			udpProxy = snap.proxy.URL
		}
		switch {
		case snap.h3ProxyError != nil:
			if snap.tcpProxyError != nil {
				return snap.h3ProxyError
			}
			return t.preconnectHTTP2(ctx, host, port, true)
		case SupportsQUIC(udpProxy) && snap.tcpProxyError != nil:
			return h3()
		case !SupportsQUIC(udpProxy):
			return t.preconnectHTTP2(ctx, host, port, true)
		}
	}

	t.protocolSupportMu.RLock()
	known, ok := t.protocolSupport[host]
	t.protocolSupportMu.RUnlock()
	if ok {
		switch known {
		case ProtocolHTTP1:
			return h1()
		case ProtocolHTTP2:
			return t.preconnectHTTP2(ctx, host, port, true)
		case ProtocolHTTP3:
			switch t.h3Broken.standing(host, time.Now()) {
			case h3Works:
				return h3()
			case h3Recheck:
				t.recheckH3(rawURL)
			}
			return t.preconnectHTTP2(ctx, host, port, true)
		}
	}

	if !snap.preset.SupportHTTP3 || snap.h3 == nil {
		return t.preconnectHTTP2(ctx, host, port, true)
	}
	decision := t.raceConnectProtocol(ctx, host, port)
	switch {
	case decision.err != nil:
		return decision.err
	case decision.alpnErr != nil:
		t.h1Transport.adoptTLSConn(decision.alpnErr.TLSConn, host, port, u.Scheme)
		t.cacheProtocol(host, ProtocolHTTP1)
		return nil
	case decision.protocol == ProtocolHTTP3:
		t.cacheProtocol(host, ProtocolHTTP3)
		return nil
	}
	// HTTP/2 won, or neither connected within the race's budget: a request
	// would go over HTTP/2 now, and its connection is what is wanted.
	return t.preconnectHTTP2(ctx, host, port, true)
}

// preconnectHTTP2 opens host's HTTP/2 connection. A server that negotiates
// HTTP/1.1 instead has its connection kept in the HTTP/1.1 pool, and, in auto
// mode (remember), the host remembered as HTTP/1.1, as a request would.
func (t *Transport) preconnectHTTP2(ctx context.Context, host, port string, remember bool) error {
	err := t.snapshot().h2.Connect(ctx, host, port)
	var alpnErr *ALPNMismatchError
	if !errors.As(err, &alpnErr) {
		if err == nil && remember {
			t.cacheProtocol(host, ProtocolHTTP2)
		}
		return err
	}
	if !remember {
		// Forced HTTP/2: a request would fail on this server too.
		alpnErr.TLSConn.Close()
		return err
	}
	t.h1Transport.adoptTLSConn(alpnErr.TLSConn, host, port, "https")
	t.cacheProtocol(host, ProtocolHTTP1)
	return nil
}

// Preconnect opens a connection to host for its next request and leaves it
// idle in the pool, unless one is idle there already.
func (t *HTTP1Transport) Preconnect(ctx context.Context, host, port, scheme string) error {
	key := fmt.Sprintf("%s://%s:%s", scheme, t.getConnectHost(host), port)
	if t.hasIdleConn(key) {
		return nil
	}
	conn, err := t.createConnRetry(ctx, host, port, scheme)
	if err != nil {
		return err
	}
	t.putIdleConn(key, conn)
	return nil
}

// hasIdleConn reports whether key has a connection idle in the pool that has
// not been idle too long.
func (t *HTTP1Transport) hasIdleConn(key string) bool {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()
	for _, conn := range t.idleConns[key] {
		if time.Since(conn.lastUsedAt) <= t.maxIdleTime {
			return true
		}
	}
	return false
}

// adoptTLSConn keeps tlsConn, a connection that negotiated HTTP/1.1 while
// opening HTTP/2, idle in the pool for host's next request.
func (t *HTTP1Transport) adoptTLSConn(tlsConn *utls.UConn, host, port, scheme string) {
	state := tlsConn.ConnectionState()
	conn := &http1Conn{
		host:           host,
		port:           port,
		conn:           tlsConn,
		tlsConn:        tlsConn,
		createdAt:      time.Now(),
		lastUsedAt:     time.Now(),
		sessionResumed: state.DidResume,
		tlsVersion:     state.Version,
		cipherSuite:    state.CipherSuite,
	}
	conn.setBuffers()
	t.putIdleConn(fmt.Sprintf("%s://%s:%s", scheme, t.getConnectHost(host), port), conn)
}
