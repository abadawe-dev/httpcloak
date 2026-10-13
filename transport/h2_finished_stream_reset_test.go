package transport

import (
	"context"
	"crypto/tls"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A request with a body whose response ends with its HEADERS frame must not
// be reset once it has finished.
//
// The read loop wakes roundTrip on the response HEADERS and only then closes
// peerClosed. The wait after it covered requests without a body, so a POST
// could return in between, and a caller that cancels its context on return
// (Transport.Do does) raced writeRequest into seeing the cancel before
// peerClosed: RST_STREAM(CANCEL) on a stream both sides had closed. Measured
// before the fix at GOMAXPROCS 8: 3 to 7 resets per 20,000 POSTs, from 1.7.2
// on. No browser sends one, so even a rare one is a tell.
//
// The race is a few instructions wide, so this samples it rather than forcing
// it, and it needs parallelism to show at all.
func TestFinishedPOSTStreamIsNotReset(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("the race needs at least two Ps to show")
	}
	cert := wireCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var resets atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				serveWireH2(c, portOf(ln.Addr()), func(s string) {
					if strings.HasPrefix(s, "RST_STREAM") {
						resets.Add(1)
					}
				}, func() {})
			}(c)
		}
	}()

	const workers, perWorker = 8, 2500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := wireTransport("chrome-latest", ProtocolHTTP2)
			defer tr.Close()
			for i := 0; i < perWorker; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err := tr.Do(ctx, &Request{Method: "POST",
					URL: "https://" + ln.Addr().String() + "/c", Body: []byte(`{"k":1}`)})
				cancel()
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	if n := resets.Load(); n != 0 {
		t.Fatalf("%d of %d finished POST streams were reset", n, workers*perWorker)
	}
}
