package httpcloak

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

type taRecConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *taRecConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		r.buf.Write(p[:n])
		r.mu.Unlock()
	}
	return n, err
}

func (r *taRecConn) recorded() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

// helloExtensions pulls the extension id order and the raw trust_anchors body
// out of a recorded ClientHello.
func helloExtensions(stream []byte) (order []uint16, trustAnchors []byte, ok bool) {
	if len(stream) < 5 || stream[0] != 0x16 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(stream[3:5]))
	if len(stream) < 5+n {
		return nil, nil, false
	}
	b := stream[5 : 5+n]
	if len(b) < 4 || b[0] != 0x01 {
		return nil, nil, false
	}
	ml := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+ml {
		return nil, nil, false
	}
	p := b[4 : 4+ml]
	if len(p) < 34 {
		return nil, nil, false
	}
	p = p[34:]
	p = p[1+int(p[0]):]                           // session id
	p = p[2+int(binary.BigEndian.Uint16(p[:2])):] // cipher suites
	p = p[1+int(p[0]):]                           // compression methods
	if len(p) < 2 {
		return nil, nil, false
	}
	el := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < el {
		return nil, nil, false
	}
	p = p[:el]
	for len(p) >= 4 {
		id := binary.BigEndian.Uint16(p[:2])
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if len(p) < 4+l {
			break
		}
		order = append(order, id)
		if id == 0xCA34 {
			trustAnchors = append([]byte(nil), p[4:4+l]...)
		}
		p = p[4+l:]
	}
	return order, trustAnchors, true
}

// TestTrustAnchorsAreStableOnTheWire is the end-to-end half of the trust_anchors
// lock. The static tests in fingerprint/ cover our own flag and stored order;
// this one catches the case where the utls fork starts permuting the list again
// underneath us, which those cannot see.
//
// The two properties are deliberately checked together, because they are
// opposites and it is the contrast that matches Chrome: the extension ORDER
// must vary per handshake, and the anchor list inside trust_anchors must not.
// Measured against Chrome 153.0.8010.52, 29 connections over three processes
// gave 29 extension orders and exactly one trust_anchors payload.
func TestTrustAnchorsAreStableOnTheWire(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	type capture struct {
		order  []uint16
		anchor []byte
	}
	var mu sync.Mutex
	var caps []capture

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := &taRecConn{Conn: c}
				tc := tls.Server(r, cfg)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if tc.HandshakeContext(ctx) != nil {
					return
				}
				if order, anchors, ok := helloExtensions(r.recorded()); ok {
					mu.Lock()
					caps = append(caps, capture{order, anchors})
					mu.Unlock()
				}
				br := bufio.NewReader(tc)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				// Close without announcing it, so the next request has to
				// open a fresh connection and handshake again.
				time.Sleep(30 * time.Millisecond)
			}(c)
		}
	}()

	sess := NewSession("chrome-153-linux", WithInsecureSkipVerify(), WithForceHTTP1())
	defer sess.Close()

	const want = 4
	for i := 0; i < want; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := sess.Get(ctx, "https://127.0.0.1:"+portOf(ln)+"/")
		if err != nil {
			cancel()
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		cancel()
		time.Sleep(120 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(caps) < 2 {
		t.Fatalf("only %d handshakes recorded, need at least 2 to compare", len(caps))
	}

	anchors := map[string]int{}
	orders := map[string]int{}
	for _, c := range caps {
		if len(c.anchor) == 0 {
			t.Fatal("a ClientHello carried no trust_anchors extension")
		}
		anchors[hex.EncodeToString(c.anchor)]++
		var b []byte
		for _, id := range c.order {
			b = binary.BigEndian.AppendUint16(b, id)
		}
		orders[hex.EncodeToString(b)]++
	}

	if len(anchors) != 1 {
		t.Errorf("%d handshakes produced %d different trust_anchors payloads; "+
			"Chrome sends one fixed list and never varies it, so two connections "+
			"from one session become linkable", len(caps), len(anchors))
		for a := range anchors {
			t.Logf("  payload: %s", a)
		}
	}
	if len(orders) < 2 {
		t.Errorf("%d handshakes produced only %d distinct extension order(s); "+
			"Chrome permutes the extension order on every handshake", len(caps), len(orders))
	}
}

func portOf(ln net.Listener) string {
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}
