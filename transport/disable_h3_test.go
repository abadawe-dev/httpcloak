package transport

import (
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// SetDisableHTTP3 keeps auto mode (#121) and still never sends a QUIC packet.
// A UDP socket bound to the server's port counts what arrives; the control,
// plain auto mode, shows that the socket sees HTTP/3 attempts when they happen.
func TestDisableHTTP3SendsNoQUIC(t *testing.T) {
	for _, tc := range []struct {
		name    string
		disable bool
		wantUDP bool
	}{
		{"auto", false, true},
		{"disable-h3", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			// A forwarder that holds each TCP connection for 400ms before
			// passing it on, so HTTP/2 does not win the race before HTTP/3
			// has had time to send anything.
			fwd, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer fwd.Close()
			go func() {
				for {
					c, err := fwd.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						time.Sleep(400 * time.Millisecond)
						up, err := net.Dial("tcp", srv.addr)
						if err != nil {
							return
						}
						defer up.Close()
						go io.Copy(up, c)
						io.Copy(c, up)
					}(c)
				}
			}()
			addr := fwd.Addr().String()
			udp, err := net.ListenPacket("udp", addr)
			if err != nil {
				t.Skipf("cannot bind UDP on the server's port: %v", err)
			}
			defer udp.Close()
			var packets atomic.Int32
			go func() {
				buf := make([]byte, 2048)
				for {
					if _, _, err := udp.ReadFrom(buf); err != nil {
						return
					}
					packets.Add(1)
				}
			}()

			tr := NewTransport("chrome-155-windows")
			tr.SetInsecureSkipVerify(true)
			tr.SetDisableHTTP3(tc.disable)
			defer tr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + addr + "/"})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.Protocol != "h2" {
				t.Errorf("protocol %q, want h2", resp.Protocol)
			}
			time.Sleep(300 * time.Millisecond)
			if got := packets.Load() > 0; got != tc.wantUDP {
				t.Errorf("%d UDP packets reached the server's port; want any: %v", packets.Load(), tc.wantUDP)
			}
		})
	}
}

// A host already learned as HTTP/3 kept being routed there after HTTP/3 was
// turned off, to a transport the snapshot no longer hands out, and both Do and
// DoStream panicked on it. Turning HTTP/3 off now forgets such hosts, and a
// request that still reaches HTTP/3 fails as unsent instead.
func TestDisablingHTTP3ForgetsHostsLearnedAsHTTP3(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr := autoTransport(t, "chrome-155")
	tr.cacheProtocol(extractHost(srv.URL), ProtocolHTTP3)
	tr.SetDisableHTTP3(true)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: srv.URL}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	// A request already in flight when HTTP/3 was turned off can still learn
	// the host as HTTP/3 afterwards; that must not panic either.
	tr.cacheProtocol(extractHost(srv.URL), ProtocolHTTP3)
	sr, err := tr.DoStream(ctx, &Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	sr.Close()
}
