package transport

import (
	"context"
	"io"
	"net"
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
