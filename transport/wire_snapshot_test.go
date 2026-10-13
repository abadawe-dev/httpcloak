package transport

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/net/http2/hpack"
	"github.com/sardanioss/quic-go"
	utls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Wire snapshot of every built-in preset.
//
// A preset is only as good as what reaches the wire, and the wire is assembled
// in several layers (the preset tables, the uTLS spec builder, the transports,
// the forks). A change in any of them can move a field nobody meant to move:
// trust_anchors drifted somewhere between the Chrome 149 and 152 presets and
// nothing failed. This test is the net under all of them. For every preset it
// records, against local servers:
//
//   - the TCP ClientHello in auto, forced HTTP/2 and forced HTTP/1.1 mode
//   - the QUIC ClientHello, decrypted from the client's Initial packets
//   - the HTTP/2 frames of three requests on one connection, with the HPACK
//     representation of every header (indexing mode, Huffman, table index)
//   - the raw HTTP/1.1 request bytes
//   - the HTTP/3 SETTINGS, PRIORITY_UPDATE frames and QPACK field lines
//   - the preset's describe JSON
//
// and compares it with transport/testdata/wire/<preset>.golden. Any difference
// fails, so every wire change has to arrive with a regenerated golden, which a
// reviewer then reads line by line:
//
//	go test ./transport/ -run TestWireSnapshot -update-wire
//
// Values that are random by design (client random, key share bytes, ECH
// payload, connection IDs) are left out. Each ClientHello is captured three
// times on fresh transports: an extension order that differs between captures
// is recorded sorted and marked permuted, and an extension whose content
// differs is recorded as the elements all three captures share.

var updateWire = flag.Bool("update-wire", false, "rewrite transport/testdata/wire goldens")

const wireCaptures = 3

func TestWireSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("wire snapshot is a long test")
	}
	cert := wireCert(t)
	names := fingerprint.Available()
	sort.Strings(names)

	sem := make(chan struct{}, 6)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			got := snapshotPreset(t, name, cert)
			path := filepath.Join("testdata", "wire", name+".golden")
			if *updateWire {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("no golden for %s (run with -update-wire): %v", name, err)
			}
			if string(want) != got {
				t.Errorf("wire snapshot for %s changed:\n%s", name, lineDiff(string(want), got))
			}
		})
	}

	// A golden whose preset is gone is a preset that was dropped; say so
	// rather than leaving the file behind.
	if !*updateWire {
		files, _ := filepath.Glob(filepath.Join("testdata", "wire", "*.golden"))
		have := map[string]bool{}
		for _, n := range names {
			have[n] = true
		}
		for _, f := range files {
			if n := strings.TrimSuffix(filepath.Base(f), ".golden"); !have[n] {
				t.Errorf("golden %s has no preset", f)
			}
		}
	}
}

func snapshotPreset(t *testing.T, name string, cert tls.Certificate) string {
	p := fingerprint.Get(name)
	if p == nil {
		t.Fatalf("preset %s missing", name)
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# %s\n", name)

	for _, m := range []struct {
		label string
		proto Protocol
	}{{"auto", ProtocolAuto}, {"h2", ProtocolHTTP2}, {"h1", ProtocolHTTP1}} {
		var hellos [][]string
		for i := 0; i < wireCaptures; i++ {
			hellos = append(hellos, captureTCPHello(t, name, m.proto))
		}
		fmt.Fprintf(&out, "\n## tcp client hello (%s)\n", m.label)
		writeMerged(&out, hellos)
	}

	fmt.Fprintf(&out, "\n## http/2\n")
	out.WriteString(captureH2(t, name, cert))
	fmt.Fprintf(&out, "\n## http/1.1\n")
	out.WriteString(captureH1(t, name, cert))

	if p.SupportHTTP3 {
		var hellos [][]string
		for i := 0; i < wireCaptures; i++ {
			hellos = append(hellos, captureQUICHello(t, name))
		}
		fmt.Fprintf(&out, "\n## quic client hello\n")
		writeMerged(&out, hellos)
		fmt.Fprintf(&out, "\n## http/3\n")
		out.WriteString(captureH3(t, name, cert))
	}

	fmt.Fprintf(&out, "\n## describe\n")
	if d, err := fingerprint.Describe(name); err != nil {
		fmt.Fprintf(&out, "error: %v\n", err)
	} else {
		out.WriteString(strings.TrimRight(d, "\n") + "\n")
	}
	return out.String()
}

// ------------------------------------------------------------ client side

func wireTransport(name string, proto Protocol) *Transport {
	tr := NewTransport(name)
	tr.SetProtocol(proto)
	tr.SetInsecureSkipVerify(true)
	return tr
}

// ------------------------------------------------------------ TCP hello

// captureTCPHello records the first ClientHello a fresh transport sends. The
// listener reads the hello and hangs up, so the request itself fails.
func captureTCPHello(t *testing.T, name string, proto Protocol) []string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		msg, _ := readTLSHandshakeMsg(c)
		got <- msg
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr := wireTransport(name, proto)
	defer tr.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Do(ctx, &Request{Method: "GET", URL: "https://" + ln.Addr().String() + "/"})
	}()

	var msg []byte
	select {
	case msg = <-got:
	case <-time.After(15 * time.Second):
	}
	cancel()
	<-done
	if msg == nil {
		t.Fatalf("%s: no TCP ClientHello captured", name)
	}
	return renderHello(t, msg)
}

// readTLSHandshakeMsg reads TLS records until one whole handshake message is
// in hand and returns its body (after the 4-byte handshake header).
func readTLSHandshakeMsg(r io.Reader) ([]byte, error) {
	var hs []byte
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		if hdr[0] != 0x16 {
			return nil, fmt.Errorf("record type %d", hdr[0])
		}
		rec := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
		if _, err := io.ReadFull(r, rec); err != nil {
			return nil, err
		}
		hs = append(hs, rec...)
		if len(hs) >= 4 {
			n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) >= 4+n {
				return hs[4 : 4+n], nil
			}
		}
	}
}

// ------------------------------------------------------------ QUIC hello

var quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// captureQUICHello reads the client's Initial packets on a bare UDP socket,
// decrypts them with the version 1 initial keys (RFC 9001 section 5.2, derived
// from the client's own destination connection ID) and reassembles the
// ClientHello from the CRYPTO frames. Nothing answers, so the request fails.
func captureQUICHello(t *testing.T, name string) []string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	type result struct {
		hello []byte
		meta  []string
		err   error
	}
	got := make(chan result, 1)
	go func() {
		crypto := map[uint64][]byte{}
		var meta []string
		buf := make([]byte, 65536)
		pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		for dgram := 0; ; dgram++ {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				got <- result{err: err}
				return
			}
			if dgram == 0 {
				meta = append(meta, fmt.Sprintf("first datagram size %d", n))
			}
			pm, err := decryptInitials(buf[:n], crypto)
			if err != nil {
				got <- result{err: err}
				return
			}
			if dgram == 0 {
				meta = append(meta, pm...)
			}
			stream := contiguous(crypto)
			if len(stream) >= 4 {
				l := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
				if len(stream) >= 4+l {
					got <- result{hello: stream[4 : 4+l], meta: meta}
					return
				}
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr := wireTransport(name, ProtocolHTTP3)
	defer tr.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Do(ctx, &Request{Method: "GET", URL: "https://" + pc.LocalAddr().String() + "/"})
	}()

	var r result
	select {
	case r = <-got:
	case <-time.After(15 * time.Second):
		r.err = errors.New("timed out")
	}
	cancel()
	<-done
	if r.err != nil {
		t.Fatalf("%s: QUIC ClientHello: %v", name, r.err)
	}
	return append(r.meta, renderHello(t, r.hello)...)
}

func contiguous(m map[uint64][]byte) []byte {
	var out []byte
	for {
		b, ok := m[uint64(len(out))]
		if !ok {
			// A frame may overlap what is already assembled.
			found := false
			for off, d := range m {
				if off < uint64(len(out)) && off+uint64(len(d)) > uint64(len(out)) {
					out = append(out, d[uint64(len(out))-off:]...)
					found = true
					break
				}
			}
			if !found {
				return out
			}
			continue
		}
		out = append(out, b...)
	}
}

// decryptInitials walks the coalesced long-header packets of one datagram,
// decrypts every version 1 Initial and files its CRYPTO frames by offset.
func decryptInitials(d []byte, crypto map[uint64][]byte) ([]string, error) {
	var meta []string
	for len(d) > 0 {
		if d[0]&0x80 == 0 {
			return meta, nil // short header: not ours to read
		}
		if len(d) < 7 {
			return meta, errors.New("short long header")
		}
		version := binary.BigEndian.Uint32(d[1:5])
		p := 5
		dcid := d[p+1 : p+1+int(d[p])]
		p += 1 + int(d[p])
		scidLen := int(d[p])
		p += 1 + scidLen
		ptype := (d[0] >> 4) & 0x3
		var tokenLen uint64
		if ptype == 0 {
			var n int
			tokenLen, n = quicVarint(d[p:])
			p += n + int(tokenLen)
		}
		length, n := quicVarint(d[p:])
		p += n
		pnOff := p
		end := pnOff + int(length)
		if end > len(d) {
			return meta, errors.New("packet runs past datagram")
		}
		if version != 1 || ptype != 0 {
			meta = append(meta, fmt.Sprintf("skipped packet version %#x type %d", version, ptype))
			d = d[end:]
			continue
		}
		meta = append(meta, fmt.Sprintf("initial: dcid %d bytes, scid %d bytes, token %d bytes",
			len(dcid), scidLen, tokenLen))

		key, iv, hp := quicClientInitialKeys(dcid)
		pkt := append([]byte(nil), d[:end]...)
		hpBlock, _ := aes.NewCipher(hp)
		var mask [16]byte
		hpBlock.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
		pkt[0] ^= mask[0] & 0x0f
		pnLen := int(pkt[0]&0x3) + 1
		var pn uint64
		for i := 0; i < pnLen; i++ {
			pkt[pnOff+i] ^= mask[1+i]
			pn = pn<<8 | uint64(pkt[pnOff+i])
		}
		nonce := append([]byte(nil), iv...)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
		}
		block, _ := aes.NewCipher(key)
		aead, _ := cipher.NewGCM(block)
		plain, err := aead.Open(nil, nonce, pkt[pnOff+pnLen:], pkt[:pnOff+pnLen])
		if err != nil {
			return meta, fmt.Errorf("initial decrypt: %w", err)
		}
		if err := collectCrypto(plain, crypto); err != nil {
			return meta, err
		}
		d = d[end:]
	}
	return meta, nil
}

func collectCrypto(b []byte, crypto map[uint64][]byte) error {
	for len(b) > 0 {
		ft, n := quicVarint(b)
		b = b[n:]
		switch ft {
		case 0x00, 0x01: // PADDING, PING
		case 0x06: // CRYPTO
			off, n1 := quicVarint(b)
			l, n2 := quicVarint(b[n1:])
			start := n1 + n2
			crypto[off] = append([]byte(nil), b[start:start+int(l)]...)
			b = b[start+int(l):]
		default:
			return fmt.Errorf("unexpected frame %#x in a client Initial", ft)
		}
	}
	return nil
}

func quicClientInitialKeys(dcid []byte) (key, iv, hp []byte) {
	secret, _ := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	client := hkdfLabel(secret, "client in", 32)
	return hkdfLabel(client, "quic key", 16), hkdfLabel(client, "quic iv", 12), hkdfLabel(client, "quic hp", 16)
}

func hkdfLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(full))}
	info = append(info, full...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), n)
	return out
}

func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, len(b)
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

// ------------------------------------------------------------ hello rendering

func isGREASE16(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func u16Name(v uint16) string {
	if isGREASE16(v) {
		return "GREASE"
	}
	return fmt.Sprintf("%d", v)
}

// helloExt is one rendered extension: its label and the elements of its body.
type helloExt struct {
	id    string
	elems []string
}

// renderHello turns a ClientHello body into lines with every per-connection
// random value removed. The first line holds the extension order; the merge
// step relies on that.
func renderHello(t *testing.T, b []byte) []string {
	r := &byteReader{b: b}
	var lines []string
	lines = append(lines, "") // extension order, filled in below
	lines = append(lines, fmt.Sprintf("legacy_version %#04x", r.u16()))
	r.skip(32) // random
	sid := r.bytes8()
	lines = append(lines, fmt.Sprintf("session_id %d bytes", len(sid)))
	suites := r.bytes16()
	var cs []string
	for i := 0; i+1 < len(suites); i += 2 {
		cs = append(cs, u16Name(binary.BigEndian.Uint16(suites[i:])))
	}
	lines = append(lines, "cipher_suites "+strings.Join(cs, ","))
	lines = append(lines, "compression "+hex.EncodeToString(r.bytes8()))
	exts := r.bytes16()
	if r.err != nil {
		t.Fatalf("ClientHello: %v", r.err)
	}
	var order []string
	er := &byteReader{b: exts}
	for len(er.b) > 0 && er.err == nil {
		id := er.u16()
		data := er.bytes16()
		e := renderExt(id, data)
		order = append(order, e.id)
		lines = append(lines, "ext "+e.id+": "+strings.Join(e.elems, " "))
	}
	if er.err != nil {
		t.Fatalf("ClientHello extensions: %v", er.err)
	}
	lines[0] = "extensions " + strings.Join(order, ",")
	return lines
}

func renderExt(id uint16, data []byte) helloExt {
	e := helloExt{id: u16Name(id)}
	if isGREASE16(id) {
		e.elems = []string{hex.EncodeToString(data)}
		return e
	}
	r := &byteReader{b: data}
	switch id {
	case 10: // supported_groups
		e.elems = u16List(r.bytes16())
	case 13, 50: // signature_algorithms, signature_algorithms_cert
		e.elems = u16List(r.bytes16())
	case 43: // supported_versions
		e.elems = u16List(r.bytes8())
	case 27: // compress_certificate
		e.elems = u16List(r.bytes8())
	case 51: // key_share: group and share length, never the share
		ks := &byteReader{b: r.bytes16()}
		for len(ks.b) > 0 && ks.err == nil {
			g := ks.u16()
			e.elems = append(e.elems, fmt.Sprintf("%s:%d", u16Name(g), len(ks.bytes16())))
		}
	case 21: // padding
		e.elems = []string{fmt.Sprintf("len=%d", len(data))}
	case 41: // pre_shared_key
		e.elems = []string{"present"}
	case 0xfe0d: // encrypted_client_hello
		// Only the shape is stable. With no ECH config the extension is
		// GREASE, and browsers randomise it per connection on purpose: Chrome
		// picks the payload length from 144, 176, 208 and 240, Firefox picks
		// the AEAD. The KDF, the encapsulated key size and the payload length
		// modulo 16 survive that and still tell the two shapes apart.
		typ := r.u8()
		e.elems = append(e.elems, fmt.Sprintf("type=%d", typ))
		if typ == 0 {
			e.elems = append(e.elems, fmt.Sprintf("kdf=%d", r.u16()))
			r.u16() // aead
			r.u8()  // config_id
			e.elems = append(e.elems, fmt.Sprintf("enc=%d", len(r.bytes16())),
				fmt.Sprintf("payload%%16=%d", len(r.bytes16())%16))
		}
	case 57, 0xffa5: // quic_transport_parameters
		e.elems = renderTransportParams(data)
	default:
		e.elems = []string{hex.EncodeToString(data)}
	}
	if r.err != nil {
		e.elems = append(e.elems, "parse-error:"+hex.EncodeToString(data))
	}
	return e
}

func u16List(b []byte) []string {
	var out []string
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, u16Name(binary.BigEndian.Uint16(b[i:])))
	}
	return out
}

func renderTransportParams(b []byte) []string {
	var out []string
	for len(b) > 0 {
		id, n := quicVarint(b)
		l, m := quicVarint(b[n:])
		if n == 0 || m == 0 || n+m+int(l) > len(b) {
			return append(out, "parse-error")
		}
		v := b[n+m : n+m+int(l)]
		b = b[n+m+int(l):]
		switch {
		case id >= 27 && (id-27)%31 == 0:
			out = append(out, "GREASE")
		case id == 0x0f: // initial_source_connection_id
			out = append(out, fmt.Sprintf("%#x=cid(%d)", id, len(v)))
		default:
			if x, k := quicVarint(v); k == len(v) && k > 0 {
				out = append(out, fmt.Sprintf("%#x=%d", id, x))
			} else {
				out = append(out, fmt.Sprintf("%#x=%s", id, hex.EncodeToString(v)))
			}
		}
	}
	return out
}

// writeMerged writes the captures of one hello. Lines identical in every
// capture are written as they are. An extension order that differs is written
// sorted and marked permuted; an extension body that differs keeps the
// elements every capture has, sorted, and is marked as varying.
func writeMerged(w *strings.Builder, caps [][]string) {
	for i, c := range caps {
		if len(c) != len(caps[0]) {
			// A different number of lines means a different set of extensions
			// between captures, which the line-by-line merge can't express.
			fmt.Fprintf(w, "capture %d has %d lines, capture 0 has %d\n", i, len(c), len(caps[0]))
		}
	}
	byExt := func(c []string) map[string]string {
		m := map[string]string{}
		for _, l := range c {
			if strings.HasPrefix(l, "ext ") {
				k := l[:strings.Index(l, ":")]
				if _, dup := m[k]; dup {
					k += "#2"
				}
				m[k] = l
			}
		}
		return m
	}
	orderOf := func(c []string) string {
		for _, l := range c {
			if strings.HasPrefix(l, "extensions ") {
				return l
			}
		}
		return ""
	}
	// Non-extension lines in capture 0 order, with the extension order in its
	// place among them.
	for _, l := range caps[0] {
		if strings.HasPrefix(l, "ext ") {
			continue
		}
		if strings.HasPrefix(l, "extensions ") {
			same := true
			for _, c := range caps[1:] {
				if orderOf(c) != l {
					same = false
				}
			}
			if same {
				w.WriteString(l + "\n")
			} else {
				ids := strings.Split(strings.TrimPrefix(l, "extensions "), ",")
				sort.Strings(ids)
				w.WriteString("extensions (permuted) " + strings.Join(ids, ",") + "\n")
			}
			continue
		}
		consistent := true
		for _, c := range caps[1:] {
			if !contains(c, l) {
				consistent = false
			}
		}
		if consistent {
			w.WriteString(l + "\n")
		} else {
			w.WriteString(l + " (varies)\n")
		}
	}
	// Extensions sorted by label so a permuted order doesn't reorder lines.
	maps := make([]map[string]string, len(caps))
	for i, c := range caps {
		maps[i] = byExt(c)
	}
	var keys []string
	for k := range maps[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		l := maps[0][k]
		consistent := true
		for _, m := range maps[1:] {
			if m[k] != l {
				consistent = false
			}
		}
		if consistent {
			w.WriteString(l + "\n")
			continue
		}
		var common []string
		for _, el := range strings.Fields(l[strings.Index(l, ":")+1:]) {
			in := true
			for _, m := range maps[1:] {
				if !contains(strings.Fields(m[k]), el) {
					in = false
				}
			}
			if in {
				common = append(common, el)
			}
		}
		sort.Strings(common)
		w.WriteString(k + ": (varies) " + strings.Join(common, " ") + "\n")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

type byteReader struct {
	b   []byte
	err error
}

func (r *byteReader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if len(r.b) < n {
		r.err = io.ErrUnexpectedEOF
		return false
	}
	return true
}
func (r *byteReader) skip(n int) {
	if r.need(n) {
		r.b = r.b[n:]
	}
}
func (r *byteReader) u8() byte {
	if !r.need(1) {
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}
func (r *byteReader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}
func (r *byteReader) take(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *byteReader) bytes8() []byte  { return r.take(int(r.u8())) }
func (r *byteReader) bytes16() []byte { return r.take(int(r.u16())) }

// ------------------------------------------------------------ HTTP/2

// captureH2 runs three requests over one HTTP/2 connection and records every
// frame the client sends, in order, except SETTINGS acknowledgements, whose
// position depends on when our own SETTINGS happened to land.
func captureH2(t *testing.T, name string, cert tls.Certificate) string {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := portOf(ln.Addr())

	var mu sync.Mutex
	var lines []string
	acks := 0
	record := func(s string) {
		mu.Lock()
		lines = append(lines, s)
		mu.Unlock()
	}
	conns := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns++
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				serveWireH2(c, port, record, func() { mu.Lock(); acks++; mu.Unlock() })
			}(c)
		}
	}()

	tr := wireTransport(name, ProtocolHTTP2)
	defer tr.Close()
	base := "https://" + ln.Addr().String()
	wireRequests(t, tr, base)
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	var out strings.Builder
	fmt.Fprintf(&out, "connections %d, settings acks %d\n", conns, acks)
	for _, l := range lines {
		out.WriteString(l + "\n")
	}
	return out.String()
}

// wireRequests is the request sequence every protocol runs: two GETs and a
// JSON POST on one transport, so connection reuse and the dynamic tables are
// part of what is recorded.
// wireRequestCount is how many requests wireRequests sends.
const wireRequestCount = 4

func wireRequests(t *testing.T, tr *Transport, base string) {
	reqs := []*Request{
		{Method: "GET", URL: base + "/a"},
		{Method: "GET", URL: base + "/b?q=1"},
		// Same shape as the one before it, so the HTTP/2 header plan cache
		// replays a cached resolution here instead of building one; without
		// a repeated shape the snapshot never runs that path.
		{Method: "GET", URL: base + "/b?q=2"},
		{Method: "POST", URL: base + "/c", Body: []byte(`{"k":1}`),
			Headers: map[string][]string{"Content-Type": {"application/json"}}},
	}
	if len(reqs) != wireRequestCount {
		t.Fatalf("wireRequests sends %d requests but wireRequestCount says %d", len(reqs), wireRequestCount)
	}
	for _, r := range reqs {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := tr.Do(ctx, r)
		cancel()
		if err != nil {
			t.Fatalf("%s %s: %v", r.Method, r.URL, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: status %d", r.Method, r.URL, resp.StatusCode)
		}
	}
}

func serveWireH2(c net.Conn, port string, record func(string), ack func()) {
	preface := make([]byte, 24)
	if _, err := io.ReadFull(c, preface); err != nil {
		return
	}
	var wmu sync.Mutex
	write := func(typ, flags byte, sid uint32, p []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		h := []byte{byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p)), typ, flags, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(h[5:], sid)
		c.Write(append(h, p...))
	}
	write(0x4, 0, 0, nil) // our SETTINGS, empty

	dec := hpack.NewDecoder(65536, nil)
	var block []byte
	var blockSID uint32
	var blockEnd bool
	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		l := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		sid := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		p := make([]byte, l)
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		switch typ {
		case 0x0: // DATA
			record(fmt.Sprintf("DATA stream=%d flags=%#x len=%d", sid, flags, l))
			if flags&0x1 != 0 {
				write(0x1, 0x5, sid, []byte{0x88})
			}
		case 0x1, 0x9: // HEADERS, CONTINUATION
			frag := p
			if typ == 0x1 {
				desc := fmt.Sprintf("HEADERS stream=%d flags=%#x", sid, flags)
				if flags&0x8 != 0 { // PADDED
					pad := int(frag[0])
					frag = frag[1 : len(frag)-pad]
					desc += fmt.Sprintf(" pad=%d", pad)
				}
				if flags&0x20 != 0 { // PRIORITY
					dep := binary.BigEndian.Uint32(frag[:4])
					desc += fmt.Sprintf(" exclusive=%v dep=%d weight=%d",
						dep>>31 == 1, dep&0x7fffffff, int(frag[4])+1)
					frag = frag[5:]
				}
				record(desc)
				block, blockSID, blockEnd = nil, sid, flags&0x1 != 0
			} else {
				record(fmt.Sprintf("CONTINUATION stream=%d flags=%#x", sid, flags))
			}
			block = append(block, frag...)
			if flags&0x4 != 0 { // END_HEADERS
				for _, l := range renderHPACK(block, dec, port) {
					record("  " + l)
				}
				if blockEnd {
					write(0x1, 0x5, blockSID, []byte{0x88})
				}
			}
		case 0x2:
			record(fmt.Sprintf("PRIORITY stream=%d %s", sid, hex.EncodeToString(p)))
		case 0x3:
			record(fmt.Sprintf("RST_STREAM stream=%d code=%d", sid, binary.BigEndian.Uint32(p)))
		case 0x4:
			if flags&0x1 != 0 {
				ack()
				continue
			}
			var s []string
			for i := 0; i+6 <= len(p); i += 6 {
				s = append(s, fmt.Sprintf("%d=%d", binary.BigEndian.Uint16(p[i:]), binary.BigEndian.Uint32(p[i+2:])))
			}
			record("SETTINGS " + strings.Join(s, " "))
			write(0x4, 0x1, 0, nil)
		case 0x6:
			record(fmt.Sprintf("PING flags=%#x", flags))
			if flags&0x1 == 0 {
				write(0x6, 0x1, 0, p)
			}
		case 0x7:
			record(fmt.Sprintf("GOAWAY code=%d", binary.BigEndian.Uint32(p[4:8])))
		case 0x8:
			record(fmt.Sprintf("WINDOW_UPDATE stream=%d increment=%d", sid, binary.BigEndian.Uint32(p)&0x7fffffff))
		default:
			record(fmt.Sprintf("FRAME type=%#x stream=%d flags=%#x len=%d", typ, sid, flags, l))
		}
	}
}

// renderHPACK lists each field line with its representation: how it is
// indexed, whether name and value are Huffman coded, and which table entry it
// refers to. The decoded pairs come from a real decoder that tracks the
// dynamic table across blocks.
func renderHPACK(block []byte, dec *hpack.Decoder, port string) []string {
	fields, err := dec.DecodeFull(block)
	if err != nil {
		return []string{"decode error: " + err.Error()}
	}
	var out []string
	b := block
	fi := 0
	for len(b) > 0 {
		var rep string
		switch {
		case b[0]&0x80 != 0:
			idx, n := hpackInt(b, 7)
			b = b[n:]
			rep = fmt.Sprintf("indexed %d", idx)
		case b[0]&0xe0 == 0x20:
			sz, n := hpackInt(b, 5)
			b = b[n:]
			out = append(out, fmt.Sprintf("table size update %d", sz))
			continue
		default:
			var kind string
			var prefix int
			switch {
			case b[0]&0xc0 == 0x40:
				kind, prefix = "incremental", 6
			case b[0]&0xf0 == 0x10:
				kind, prefix = "never-indexed", 4
			default:
				kind, prefix = "without-indexing", 4
			}
			idx, n := hpackInt(b, prefix)
			b = b[n:]
			name := fmt.Sprintf("name=%d", idx)
			if idx == 0 {
				_, h, n := hpackString(b, 7)
				b = b[n:]
				name = fmt.Sprintf("name=literal huffman=%v", h)
			}
			_, h, n := hpackString(b, 7)
			b = b[n:]
			rep = fmt.Sprintf("%s %s value-huffman=%v", kind, name, h)
		}
		f := "?"
		if fi < len(fields) {
			f = fields[fi].Name + ": " + strings.ReplaceAll(fields[fi].Value, port, "PORT")
		}
		fi++
		out = append(out, fmt.Sprintf("%-60s %s", rep, f))
	}
	return out
}

// hpackInt decodes an HPACK/QPACK prefixed integer (RFC 7541 5.1).
func hpackInt(b []byte, prefix int) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	max := uint64(1)<<prefix - 1
	v := uint64(b[0]) & max
	if v < max {
		return v, 1
	}
	var m uint
	for i := 1; i < len(b); i++ {
		v += uint64(b[i]&0x7f) << m
		m += 7
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return v, len(b)
}

// hpackString decodes a string literal whose length has the given prefix and
// whose Huffman flag is the bit just above it.
func hpackString(b []byte, prefix int) (string, bool, int) {
	if len(b) == 0 {
		return "", false, 0
	}
	h := b[0]&(1<<prefix) != 0
	l, n := hpackInt(b, prefix)
	if n+int(l) > len(b) {
		return "", h, len(b)
	}
	raw := b[n : n+int(l)]
	if h {
		s, err := hpack.HuffmanDecodeToString(raw)
		if err != nil {
			return "<bad huffman>", h, n + int(l)
		}
		return s, h, n + int(l)
	}
	return string(raw), h, n + int(l)
}

// ------------------------------------------------------------ HTTP/1.1

func captureH1(t *testing.T, name string, cert tls.Certificate) string {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := portOf(ln.Addr())

	var mu sync.Mutex
	var lines []string
	conns := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns++
			conn := conns
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				r := &lineReader{c: c}
				for {
					head, err := r.until("\r\n\r\n")
					if err != nil {
						return
					}
					cl := 0
					for _, l := range strings.Split(head, "\r\n") {
						if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "content-length") {
							cl, _ = strconv.Atoi(strings.TrimSpace(v))
						}
					}
					body, err := r.n(cl)
					if err != nil {
						return
					}
					mu.Lock()
					lines = append(lines, fmt.Sprintf("--- request on connection %d", conn))
					for _, l := range strings.Split(strings.TrimSuffix(head, "\r\n\r\n"), "\r\n") {
						lines = append(lines, strings.ReplaceAll(l, port, "PORT"))
					}
					if cl > 0 {
						lines = append(lines, fmt.Sprintf("body %q", body))
					}
					mu.Unlock()
					c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				}
			}(c)
		}
	}()

	tr := wireTransport(name, ProtocolHTTP1)
	defer tr.Close()
	wireRequests(t, tr, "https://"+ln.Addr().String())
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	return strings.Join(lines, "\n") + "\n"
}

type lineReader struct {
	c   net.Conn
	buf []byte
}

func (r *lineReader) until(sep string) (string, error) {
	for {
		if i := bytes.Index(r.buf, []byte(sep)); i >= 0 {
			s := string(r.buf[:i+len(sep)])
			r.buf = r.buf[i+len(sep):]
			return s, nil
		}
		tmp := make([]byte, 4096)
		n, err := r.c.Read(tmp)
		if n == 0 && err != nil {
			return "", err
		}
		r.buf = append(r.buf, tmp[:n]...)
	}
}

func (r *lineReader) n(n int) ([]byte, error) {
	for len(r.buf) < n {
		tmp := make([]byte, 4096)
		k, err := r.c.Read(tmp)
		if k == 0 && err != nil {
			return nil, err
		}
		r.buf = append(r.buf, tmp[:k]...)
	}
	out := r.buf[:n]
	r.buf = r.buf[n:]
	return out, nil
}

// ------------------------------------------------------------ HTTP/3

// captureH3 runs the request sequence over HTTP/3 against a bare QUIC server
// that speaks just enough HTTP/3 to answer, and records the client's control
// stream frames, the types of its other unidirectional streams, and the QPACK
// field lines of each request.
func captureH3(t *testing.T, name string, cert tls.Certificate) string {
	ln, err := quic.ListenAddr("127.0.0.1:0", &utls.Config{
		Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos:   []string{"h3"}},
		&quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := portOf(ln.Addr())

	var mu sync.Mutex
	var control, uni []string
	requests := map[uint64][]string{}
	conns := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			conns++
			mu.Unlock()
			if s, err := conn.OpenUniStream(); err == nil {
				s.Write([]byte{0x00, 0x04, 0x00}) // control stream, empty SETTINGS
			}
			go func() {
				for {
					s, err := conn.AcceptUniStream(ctx)
					if err != nil {
						return
					}
					go func() {
						r := &quicReader{r: s}
						typ := r.varint()
						if r.err != nil {
							return
						}
						if typ != 0x00 {
							label := fmt.Sprintf("%#x", typ)
							if typ >= 0x21 && (typ-0x21)%0x1f == 0 {
								label = "GREASE"
							}
							mu.Lock()
							uni = append(uni, label)
							mu.Unlock()
							io.Copy(io.Discard, s)
							return
						}
						for {
							ft := r.varint()
							p := r.take(int(r.varint()))
							if r.err != nil {
								return
							}
							line := renderH3ControlFrame(ft, p)
							mu.Lock()
							control = append(control, line)
							mu.Unlock()
						}
					}()
				}
			}()
			go func() {
				for {
					s, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						defer s.Close()
						r := &quicReader{r: s}
						var lines []string
						for {
							ft := r.varint()
							if r.err != nil {
								break
							}
							p := r.take(int(r.varint()))
							if r.err != nil {
								break
							}
							switch {
							case ft == 0x01:
								lines = append(lines, "HEADERS")
								for _, l := range renderQPACK(p, port) {
									lines = append(lines, "  "+l)
								}
							case ft == 0x00:
								lines = append(lines, fmt.Sprintf("DATA len=%d", len(p)))
							case ft >= 0x21 && (ft-0x21)%0x1f == 0:
								lines = append(lines, "GREASE frame")
							default:
								lines = append(lines, fmt.Sprintf("FRAME %#x len=%d", ft, len(p)))
							}
						}
						mu.Lock()
						requests[uint64(s.StreamID())] = lines
						mu.Unlock()
						s.Write([]byte{0x01, 0x03, 0x00, 0x00, 0xd9}) // HEADERS :status 200
					}()
				}
			}()
		}
	}()

	tr := wireTransport(name, ProtocolHTTP3)
	defer tr.Close()
	wireRequests(t, tr, "https://"+ln.Addr().String())

	// Control-stream frames travel on their own stream, so a PRIORITY_UPDATE
	// can arrive after the response to its request has gone back. A fixed
	// 100ms sleep lost that race under -race now and then, and the snapshot
	// came out missing control lines. Wait for every request stream, then for
	// the control stream to go quiet.
	settled := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return len(requests), len(control)
	}
	deadline := time.Now().Add(5 * time.Second)
	for lastControl, quietSince := -1, time.Now(); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		nreq, nctl := settled()
		if nctl != lastControl {
			lastControl, quietSince = nctl, time.Now()
		}
		if nreq >= wireRequestCount && time.Since(quietSince) >= 250*time.Millisecond {
			break
		}
	}

	mu.Lock()
	defer mu.Unlock()
	var out strings.Builder
	fmt.Fprintf(&out, "connections %d\n", conns)
	sort.Strings(uni)
	fmt.Fprintf(&out, "uni streams %s\n", strings.Join(uni, ","))
	for _, l := range control {
		out.WriteString("control " + l + "\n")
	}
	var ids []uint64
	for id := range requests {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		fmt.Fprintf(&out, "--- request stream %d\n", id)
		for _, l := range requests[id] {
			out.WriteString(l + "\n")
		}
	}
	return out.String()
}

func renderH3ControlFrame(ft uint64, p []byte) string {
	switch {
	case ft == 0x04:
		var s []string
		for len(p) > 0 {
			id, n := quicVarint(p)
			v, m := quicVarint(p[n:])
			if n == 0 || m == 0 {
				break
			}
			p = p[n+m:]
			if id >= 0x21 && (id-0x21)%0x1f == 0 {
				s = append(s, "GREASE")
			} else {
				s = append(s, fmt.Sprintf("%#x=%d", id, v))
			}
		}
		return "SETTINGS " + strings.Join(s, " ")
	case ft == 0xf0700 || ft == 0xf0701:
		id, n := quicVarint(p)
		return fmt.Sprintf("PRIORITY_UPDATE %#x element=%d %q", ft, id, p[n:])
	case ft >= 0x21 && (ft-0x21)%0x1f == 0:
		return "GREASE frame"
	default:
		return fmt.Sprintf("FRAME %#x len=%d", ft, len(p))
	}
}

// renderQPACK lists QPACK field lines (RFC 9204 4.5) with their
// representation and, for literals, the decoded values.
func renderQPACK(b []byte, port string) []string {
	var out []string
	ric, n := hpackInt(b, 8)
	b = b[n:]
	if len(b) == 0 {
		return []string{"truncated prefix"}
	}
	sign := b[0]&0x80 != 0
	base, n := hpackInt(b, 7)
	b = b[n:]
	out = append(out, fmt.Sprintf("required-insert-count=%d base-sign=%v delta-base=%d", ric, sign, base))
	norm := func(s string) string { return strings.ReplaceAll(s, port, "PORT") }
	for len(b) > 0 {
		switch {
		case b[0]&0x80 != 0: // indexed field line
			static := b[0]&0x40 != 0
			idx, n := hpackInt(b, 6)
			b = b[n:]
			out = append(out, fmt.Sprintf("indexed static=%v %d", static, idx))
		case b[0]&0xc0 == 0x40: // literal with name reference
			never := b[0]&0x20 != 0
			static := b[0]&0x10 != 0
			idx, n := hpackInt(b, 4)
			b = b[n:]
			v, h, n := hpackString(b, 7)
			b = b[n:]
			out = append(out, fmt.Sprintf("literal name-ref static=%v %d never=%v huffman=%v %q",
				static, idx, never, h, norm(v)))
		case b[0]&0xe0 == 0x20: // literal with literal name
			never := b[0]&0x10 != 0
			name, hn, n := hpackString(b, 3)
			b = b[n:]
			v, hv, n := hpackString(b, 7)
			b = b[n:]
			out = append(out, fmt.Sprintf("literal name=%q name-huffman=%v never=%v huffman=%v %q",
				name, hn, never, hv, norm(v)))
		case b[0]&0xf0 == 0x10: // indexed post-base
			idx, n := hpackInt(b, 4)
			b = b[n:]
			out = append(out, fmt.Sprintf("indexed post-base %d", idx))
		default: // literal with post-base name reference
			never := b[0]&0x08 != 0
			idx, n := hpackInt(b, 3)
			b = b[n:]
			v, h, n := hpackString(b, 7)
			b = b[n:]
			out = append(out, fmt.Sprintf("literal post-base %d never=%v huffman=%v %q", idx, never, h, norm(v)))
		}
	}
	return out
}

type quicReader struct {
	r   io.Reader
	err error
}

func (q *quicReader) varint() uint64 {
	if q.err != nil {
		return 0
	}
	var first [1]byte
	if _, q.err = io.ReadFull(q.r, first[:]); q.err != nil {
		return 0
	}
	n := 1 << (first[0] >> 6)
	buf := make([]byte, n)
	buf[0] = first[0]
	if n > 1 {
		if _, q.err = io.ReadFull(q.r, buf[1:]); q.err != nil {
			return 0
		}
	}
	v, _ := quicVarint(buf)
	return v
}

func (q *quicReader) take(n int) []byte {
	if q.err != nil {
		return nil
	}
	b := make([]byte, n)
	_, q.err = io.ReadFull(q.r, b)
	return b
}

// ------------------------------------------------------------ helpers

func portOf(a net.Addr) string {
	_, p, _ := net.SplitHostPort(a.String())
	return p
}

func wireCert(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// lineDiff is a minimal line diff: it reports each line that is only in one
// side, in order, which is enough to read a golden change.
func lineDiff(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	// Longest common subsequence over lines.
	dp := make([][]int, len(w)+1)
	for i := range dp {
		dp[i] = make([]int, len(g)+1)
	}
	for i := len(w) - 1; i >= 0; i-- {
		for j := len(g) - 1; j >= 0; j-- {
			if w[i] == g[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < len(w) || j < len(g) {
		switch {
		case i < len(w) && j < len(g) && w[i] == g[j]:
			i++
			j++
		case j < len(g) && (i == len(w) || dp[i][j+1] >= dp[i+1][j]):
			out.WriteString("+ " + g[j] + "\n")
			j++
		default:
			out.WriteString("- " + w[i] + "\n")
			i++
		}
	}
	return out.String()
}
