package transport

import (
	"fmt"
	"net"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
)

func serveH3On(t *testing.T, conn net.PacketConn, allow0RTT bool, handler shttp.HandlerFunc) *http3.Server {
	t.Helper()
	srv := &http3.Server{
		TLSConfig:  h3RaceTestTLS(t), // a fresh key each time: an old ticket cannot resume
		QUICConfig: &quic.Config{Allow0RTT: allow0RTT},
		Handler:    handler,
	}
	go func() { _ = srv.Serve(conn) }()
	time.Sleep(100 * time.Millisecond)
	return srv
}

// Issue #127. A server that rejects 0-RTT must cost only its own connection,
// and the retry must be a full handshake. The rejection used to close and
// rebuild the whole transport, which ended every other origin's connections
// and failed their requests in flight; and every dial path put the session
// cache back, so each retry resumed, offered 0-RTT and was rejected again
// until the request failed.
func TestHTTP3ZeroRTTRejectionStaysWithItsOrigin(t *testing.T) {
	ok := shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) { w.WriteHeader(200) })
	slow := shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.WriteHeader(200)
	})

	aConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	aPort := aConn.LocalAddr().(*net.UDPAddr).Port
	a := serveH3On(t, aConn, true, ok)
	bURL := startH3Origin(t, slow)

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	aURL := fmt.Sprintf("https://127.0.0.1:%d/", aPort)
	if err := h3Fetch(tr, aURL); err != nil {
		t.Fatalf("first visit to A: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // the ticket arrives after the response

	// A restarts with a new key, so the ticket the next visit offers early
	// data on cannot be decrypted and the early data is rejected. 0-RTT stays
	// allowed so the recovered connection's new ticket can be checked below.
	a.Close()
	aConn.Close()
	aConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: aPort})
	if err != nil {
		t.Fatal(err)
	}
	defer aConn.Close()
	a = serveH3On(t, aConn, true, ok)
	defer a.Close()

	bDone := make(chan error, 1)
	go func() { bDone <- h3Fetch(tr, bURL) }()
	time.Sleep(300 * time.Millisecond) // B's request is in flight

	if err := h3Fetch(tr, aURL); err != nil {
		t.Errorf("revisit to A after it rejected 0-RTT: %v", err)
	}
	if err := <-bDone; err != nil {
		t.Errorf("B's request in flight failed when A rejected 0-RTT: %v", err)
	}

	// The rejection costs one ticket, not the host: the full handshake that
	// recovered picked up a new one, and the next connection resumes with it,
	// as a browser's would.
	time.Sleep(200 * time.Millisecond)
	tr.closeOrigin(fmt.Sprintf("127.0.0.1:%d", aPort))
	if err := h3Fetch(tr, aURL); err != nil {
		t.Fatalf("third visit to A: %v", err)
	}
	if !tr.Stats().SessionResumed {
		t.Error("the connection after the recovery did not resume; one rejection " +
			"should not keep a host on full handshakes for good")
	}
}
