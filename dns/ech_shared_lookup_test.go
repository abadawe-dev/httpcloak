package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// slowECHServer answers every HTTPS query with an ECH config after delay.
func slowECHServer(t *testing.T, delay time.Duration, ech []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		time.Sleep(delay)
		resp := new(mdns.Msg)
		resp.SetReply(req)
		rr := &mdns.HTTPS{SVCB: mdns.SVCB{
			Hdr:      mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeHTTPS, Class: mdns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value:    []mdns.SVCBKeyValue{&mdns.SVCBECHConfig{ECH: ech}},
		}}
		resp.Answer = append(resp.Answer, rr)
		w.WriteMsg(resp)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

// Concurrent dials to one host share a single HTTPS lookup. A caller waited in
// singleflight's Do, which takes no context, so a cancelled dial stayed blocked
// until the whole lookup finished. The lookup now runs detached from the
// caller that started it, and that caller's cancellation leaves the others
// with their answer.
func TestECHLookupSurvivesTheCallerThatStartedIt(t *testing.T) {
	want := []byte("ech-config-bytes")
	SetECHDNSServers([]string{slowECHServer(t, 300*time.Millisecond, want)})
	t.Cleanup(func() { SetECHDNSServers(nil) })

	const host = "ech-shared-lookup.example"
	InvalidateECHConfig(host)
	t.Cleanup(func() { InvalidateECHConfig(host) })

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := FetchECHConfigs(leaderCtx, host)
		leaderDone <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the first caller start the lookup

	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWaiter()
	waiterDone := make(chan []byte, 1)
	go func() {
		got, _ := FetchECHConfigs(waiterCtx, host)
		waiterDone <- got
	}()
	time.Sleep(50 * time.Millisecond)
	cancelLeader()

	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled caller returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Error("the cancelled caller kept waiting on the shared lookup")
	}
	if got := <-waiterDone; string(got) != string(want) {
		t.Fatalf("waiter got %q; the first caller's cancellation failed the lookup it shared", got)
	}
}
