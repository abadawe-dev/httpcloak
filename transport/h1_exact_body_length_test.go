package transport

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

func TestH1ExactBodyHasOneContentLength(t *testing.T) {
	for _, body := range [][]byte{[]byte("exact request body"), {}} {
		for _, name := range []string{"Content-Length", "content-length", "cOnTeNt-LeNgTh", ""} {
			t.Run(fmt.Sprintf("%s/%d", name, len(body)), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				type capture struct {
					head string
					body []byte
					err  error
				}
				captured := make(chan capture, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						captured <- capture{err: err}
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					reader := bufio.NewReader(conn)
					var head strings.Builder
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							captured <- capture{err: err}
							return
						}
						head.WriteString(line)
						if line == "\r\n" {
							break
						}
					}
					got := make([]byte, len(body))
					_, err = io.ReadFull(reader, got)
					fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					captured <- capture{head.String(), got, err}
				}()
				headers := []fingerprint.HeaderPair{{Key: "User-Agent", Value: "NativeSDK/1"}}
				if name != "" {
					headers = append(headers, fingerprint.HeaderPair{Key: name, Value: fmt.Sprint(len(body))})
				}
				headers = append(headers, fingerprint.HeaderPair{Key: "X-After", Value: "tail"})
				tr := NewTransport("chrome-146")
				tr.SetProtocol(ProtocolHTTP1)
				defer tr.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_, err = tr.Do(ctx, &Request{Method: "POST", URL: "http://" + listener.Addr().String() + "/", ExactHeaders: headers, Body: body})
				if err != nil {
					t.Fatal(err)
				}
				got := <-captured
				if got.err != nil {
					t.Fatal(got.err)
				}
				t.Logf("raw wire: %q body: %q", got.head, got.body)
				var lengths []string
				for _, line := range strings.Split(got.head, "\r\n") {
					if strings.HasPrefix(strings.ToLower(line), "content-length:") {
						lengths = append(lengths, line)
					}
				}
				wantName := name
				if wantName == "" {
					wantName = "Content-Length"
				}
				want := fmt.Sprintf("%s: %d", wantName, len(body))
				if len(lengths) != 1 || lengths[0] != want {
					t.Errorf("Content-Length lines = %q, want exactly %q", lengths, want)
				}
				if name != "" && !strings.Contains(got.head, want+"\r\nX-After: tail") {
					t.Errorf("explicit length lost its position: %q", got.head)
				}
				if !bytes.Equal(got.body, body) {
					t.Errorf("body = %q", got.body)
				}
			})
		}
	}
}
