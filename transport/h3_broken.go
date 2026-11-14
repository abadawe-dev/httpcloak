package transport

import (
	"context"
	"net/url"
	"sync"
	"time"
)

// brokenH3 remembers the hosts HTTP/3 stopped working for, as Chrome's
// BrokenAlternativeServices remembers a broken alternative service: auto mode
// sends a host's requests over HTTP/2 while HTTP/3 is broken for it, and tries
// HTTP/3 again when the brokenness expires.
//
// The periods are Chrome's (net/http/broken_alternative_services.cc with the
// kInitialDelayForBrokenAlternativeService and kMaxDelayForBrokenAlternativeService
// features, both enabled by default): 10 s the first time, doubling each time
// HTTP/3 fails again before it has worked, up to 30 minutes; a success clears
// the record (Confirm).
//
// Before it, a host that had worked over HTTP/3 was sent over HTTP/3 for the
// life of the session. When UDP stopped getting through (a VPN came up, a
// router shed UDP, the store turned HTTP/3 off at its edge) every request to
// it failed after about ten seconds until the session was rebuilt.
type brokenH3 struct {
	mu    sync.Mutex
	hosts map[string]*h3Breakage
}

type h3Breakage struct {
	until time.Time
	// count is how many times HTTP/3 was marked broken for the host since it
	// last worked; it sets how long the next marking lasts.
	count int
	// rechecking is set while a connection attempt checks, after the
	// brokenness expired, whether HTTP/3 works again.
	rechecking bool
}

const (
	brokenH3Initial = 10 * time.Second
	brokenH3Max     = 30 * time.Minute
)

// h3Standing is what auto mode does with a host it knows speaks HTTP/3.
type h3Standing int

const (
	// h3Works: send over HTTP/3.
	h3Works h3Standing = iota
	// h3IsBroken: send over HTTP/2.
	h3IsBroken
	// h3Recheck: the brokenness has expired. Send over HTTP/2, and check in
	// the background whether HTTP/3 connects again; the caller who is told
	// this starts the check.
	h3Recheck
)

func (b *brokenH3) standing(host string, now time.Time) h3Standing {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.hosts[host]
	switch {
	case e == nil:
		return h3Works
	case now.Before(e.until), e.rechecking:
		return h3IsBroken
	}
	e.rechecking = true
	return h3Recheck
}

// mark records that HTTP/3 failed for host.
func (b *brokenH3) mark(host string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.hosts == nil {
		b.hosts = make(map[string]*h3Breakage)
	}
	e := b.hosts[host]
	if e == nil {
		e = &h3Breakage{}
		b.hosts[host] = e
	}
	delay := brokenH3Max
	if e.count < 18 { // Chrome's kBrokenDelayMaxShift; 10 s << 18 is far past the cap
		delay = min(brokenH3Initial<<e.count, brokenH3Max)
	}
	e.until = now.Add(delay)
	e.count++
	e.rechecking = false
}

// confirm records that HTTP/3 worked for host.
func (b *brokenH3) confirm(host string) {
	b.mu.Lock()
	delete(b.hosts, host)
	b.mu.Unlock()
}

// h3RecheckTimeout bounds the connection attempt that checks whether HTTP/3
// works again for a host. It is Chrome's limit on a QUIC handshake
// (quic::kMaxTimeForCryptoHandshakeSecs, max_time_before_crypto_handshake).
const h3RecheckTimeout = 10 * time.Second

// recheckH3 tries, in the background, to open host's HTTP/3 connection,
// without a request, and records whether it worked. A connection that opens
// stays in the pool, and the host's next request goes out on it. A browser
// does the same: once the brokenness expires it races QUIC against TCP again,
// and keeps the QUIC session for later requests whichever wins.
func (t *Transport) recheckH3(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	h3 := t.snapshot().h3
	if h3 == nil {
		// HTTP/3 was turned off since the request was routed: nothing to check.
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), h3RecheckTimeout)
		defer cancel()
		if err := h3.Connect(ctx, host, port); err != nil {
			t.h3Broken.mark(host, time.Now())
			return
		}
		t.h3Broken.confirm(host)
	}()
}

// h3PathFailed reports whether an HTTP/3 attempt at req failed in a way that
// HTTP/2 can recover from without sending it twice: nothing of it was sent,
// or the path went silent under it (h3PathError) and it may be sent again
// (canResendOnAnotherProtocol).
func h3PathFailed(req *Request, err error) bool {
	return RequestNotSent(err) || (isH3PathError(err) && canResendOnAnotherProtocol(req, err))
}

// doHTTP3OrHTTP2 sends req to host, which auto mode knows speaks HTTP/3: over
// HTTP/3 unless HTTP/3 is broken for it, and over HTTP/2 when the HTTP/3
// attempt failed in a way h3PathFailed allows, within the request's deadline.
// HTTP/3 is marked broken for the host when HTTP/2 then got the answer: the
// host is up, and QUIC is what failed to reach it.
func (t *Transport) doHTTP3OrHTTP2(ctx context.Context, req *Request, host string) (*Response, error) {
	switch t.h3Broken.standing(host, time.Now()) {
	case h3IsBroken:
		return t.doHTTP2OrHTTP1(ctx, req)
	case h3Recheck:
		t.recheckH3(req.URL)
		return t.doHTTP2OrHTTP1(ctx, req)
	}
	resp, err := t.doHTTP3(ctx, req, true)
	if err == nil {
		t.h3Broken.confirm(host)
		return resp, nil
	}
	if ctx.Err() != nil || !h3PathFailed(req, err) {
		return nil, err
	}
	resp, retryErr := t.doHTTP2OrHTTP1(ctx, req)
	if retryErr != nil {
		return nil, laterAttempt(err, retryErr)
	}
	t.h3Broken.mark(host, time.Now())
	return resp, nil
}
