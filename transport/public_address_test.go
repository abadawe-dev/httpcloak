package transport

import (
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	shttp "github.com/sardanioss/http"
)

func TestIsPublic(t *testing.T) {
	public := []string{
		"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0",
		"192.167.255.255", "169.253.255.255", "223.255.255.255", "2606:4700::1111",
		"2001:4860:4860::8888", "::ffff:8.8.8.8", "::8.8.8.8", "fe00::1", "fbff::1",
	}
	local := []string{
		// This machine.
		"127.0.0.1", "127.255.255.254", "::1", "0.0.0.0", "::", "0.1.2.3",
		// Private networks: RFC 1918, RFC 6598's shared space, IPv6 unique local.
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "100.127.255.255",
		"fc00::1", "fd12:3456::1",
		// Link-local, broadcast, multicast.
		"169.254.169.254", "fe80::1", "255.255.255.255", "224.0.0.1", "239.255.255.250", "ff02::1",
		// The same, spelled as IPv4-mapped and IPv4-compatible IPv6.
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:192.168.0.1", "::ffff:100.64.0.1",
		"::ffff:169.254.169.254", "::ffff:0.0.0.0", "::127.0.0.1", "::10.0.0.1", "::192.168.0.1",
	}
	for _, s := range public {
		if !isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s is public", s)
		}
	}
	for _, s := range local {
		if isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s is not public", s)
		}
	}
	if isPublic(netip.Addr{}) {
		t.Error("no address is not public")
	}
}

// at returns rawURL with its host replaced by host, keeping the port.
func at(t *testing.T, rawURL, host string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = net.JoinHostPort(host, u.Port())
	return u.String()
}

// localTLSServer serves 200 over TLS (HTTP/2 and HTTP/1.1) on 127.0.0.1 and
// counts the connections it accepts.
func localTLSServer(t *testing.T) (string, *countingListener) {
	t.Helper()
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Write([]byte("ok"))
	}))
	l := &countingListener{Listener: srv.Listener}
	srv.Listener = l
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, l
}

func publicOnlyTransport(t *testing.T, proxy *ProxyConfig, protocol Protocol, publicOnly bool) *Transport {
	t.Helper()
	tr := NewTransportWithConfig("chrome-latest", proxy, &TransportConfig{PublicAddressesOnly: publicOnly})
	tr.SetInsecureSkipVerify(true)
	tr.SetDisableECH(true)
	tr.SetProtocol(protocol)
	t.Cleanup(tr.Close)
	return tr
}

// refusedAsLocal fails the test unless err is the guard's refusal, from
// before anything was sent.
func refusedAsLocal(t *testing.T, err error) {
	t.Helper()
	var local *LocalAddressError
	if !errors.As(err, &local) {
		t.Fatalf("got %v, want a LocalAddressError", err)
	}
	if !RequestNotSent(err) {
		t.Fatalf("%v is not marked as not sent", err)
	}
	if !strings.Contains(err.Error(), "public address") {
		t.Fatalf("%q does not say why it was refused", err)
	}
}

// A transport that connects to public addresses only refuses a name that
// resolves to this machine, and an address of this machine however it is
// spelled, on every protocol, before a connection is made; the same requests
// go through without it.
func TestPublicAddressesOnlyRefusesLocalAddressesOverTCP(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolHTTP1, ProtocolHTTP2, ProtocolAuto} {
		t.Run(protocol.String(), func(t *testing.T) {
			srv, l := localTLSServer(t)
			if err := doGetErr(t, publicOnlyTransport(t, nil, protocol, false), at(t, srv, "localhost")); err != nil {
				t.Fatalf("without the guard the local server answers: %v", err)
			}
			l.accepted.Store(0)

			tr := publicOnlyTransport(t, nil, protocol, true)
			for _, host := range []string{"localhost", "127.0.0.1", "::ffff:127.0.0.1", "::1"} {
				refusedAsLocal(t, doGetErr(t, tr, at(t, srv, host)))
			}
			if n := l.accepted.Load(); n != 0 {
				t.Fatalf("the server accepted %d connections", n)
			}
		})
	}
}

// Plain HTTP goes out on HTTP/1.1, through the same guard.
func TestPublicAddressesOnlyRefusesLocalAddressesOverPlainHTTP(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}))
	l := &countingListener{Listener: srv.Listener}
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)

	refusedAsLocal(t, doGetErr(t, publicOnlyTransport(t, nil, ProtocolAuto, true), at(t, srv.URL, "localhost")))
	if n := l.accepted.Load(); n != 0 {
		t.Fatalf("the server accepted %d connections", n)
	}
}

func TestPublicAddressesOnlyRefusesLocalAddressesOverHTTP3(t *testing.T) {
	var served atomic.Int32
	origin := startH3Origin(t, func(w shttp.ResponseWriter, r *shttp.Request) {
		served.Add(1)
		w.WriteHeader(200)
	})
	if err := doGetErr(t, publicOnlyTransport(t, nil, ProtocolHTTP3, false), origin); err != nil {
		t.Fatalf("without the guard the local server answers: %v", err)
	}
	served.Store(0)

	tr := publicOnlyTransport(t, nil, ProtocolHTTP3, true)
	for _, host := range []string{"localhost", "127.0.0.1", "::ffff:127.0.0.1"} {
		refusedAsLocal(t, doGetErr(t, tr, at(t, origin, host)))
	}
	if n := served.Load(); n != 0 {
		t.Fatalf("the server served %d requests", n)
	}
}

// Through a proxy nothing is checked: the proxy, which may well be on this
// machine, is reached, and it resolves the request's host on its own network.
func TestPublicAddressesOnlyLeavesAProxyToResolve(t *testing.T) {
	srv, l := localTLSServer(t)
	for _, protocol := range []Protocol{ProtocolHTTP1, ProtocolHTTP2, ProtocolAuto} {
		t.Run(protocol.String(), func(t *testing.T) {
			tr := publicOnlyTransport(t, &ProxyConfig{URL: connectProxy(t, "")}, protocol, true)
			if err := doGetErr(t, tr, at(t, srv, "localhost")); err != nil {
				t.Fatalf("through a proxy: %v", err)
			}
		})
	}
	if l.accepted.Load() == 0 {
		t.Fatal("the proxy never reached the server")
	}
}
