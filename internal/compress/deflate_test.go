package compress

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
	"strings"
	"testing"
	"time"
)

var body = []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200))

func zlibOf(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func rawOf(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// Both framings decode, which is the point of #115: the zlib one is what RFC
// 9110 specifies and was the one that failed.
func TestDeflateDecodesBothFramings(t *testing.T) {
	for name, enc := range map[string][]byte{
		"zlib (RFC 1950, as RFC 9110 specifies)": zlibOf(t, body),
		"raw (RFC 1951, what many servers send)": rawOf(t, body),
		"zlib, tiny body":                        zlibOf(t, []byte("x")),
		"raw, tiny body":                         rawOf(t, []byte("x")),
	} {
		got, err := InflateDeflate(enc)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want := body
		if strings.Contains(name, "tiny") {
			want = []byte("x")
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: decoded %d bytes, want %d", name, len(got), len(want))
		}
	}
}

// A raw stream can begin with two bytes that form a valid zlib header. Chrome
// inflates it as zlib, hits an error before any output, and restarts as raw;
// a check on the header alone would commit to zlib and fail.
//
// 78 01 is a valid zlib header (method 8, 32K window, checksum ok, no
// dictionary), and also a raw stored block: BFINAL=0, BTYPE=00, LEN=0x0001,
// NLEN=0xfffe, one byte of data, then an empty final fixed block.
func TestDeflateFallsBackToRawWhenZlibFailsEarly(t *testing.T) {
	raw := []byte{0x78, 0x01, 0x00, 0xfe, 0xff, 'X', 0x03, 0x00}
	if _, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw))); err != nil {
		t.Fatalf("fixture is not valid raw deflate: %v", err)
	}
	if _, err := zlib.NewReader(bytes.NewReader(raw)); err != nil {
		t.Fatalf("fixture's first two bytes are not a valid zlib header: %v", err)
	}
	got, err := InflateDeflate(raw)
	if err != nil || string(got) != "X" {
		t.Fatalf("got %q, %v; want \"X\" decoded as raw after the zlib attempt fails", got, err)
	}
}

func TestDeflateEmptyBodyIsEmpty(t *testing.T) {
	got, err := InflateDeflate(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

// A preset dictionary is never usable here, and neither framing decodes it, so
// it must fail rather than return garbage.
func TestDeflateZlibWithPresetDictionaryFails(t *testing.T) {
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevelDict(&buf, zlib.DefaultCompression, []byte("dict"))
	w.Write(body)
	w.Close()
	if _, err := InflateDeflate(buf.Bytes()); err == nil {
		t.Fatal("decoded a body that needs a preset dictionary")
	}
}

// A zlib body whose data is corrupt after it has started producing output is
// committed to zlib and fails, as in Chrome, rather than being retried as raw.
func TestDeflateCorruptZlibAfterOutputFails(t *testing.T) {
	enc := zlibOf(t, body)
	enc[len(enc)-1] ^= 0xff // break the Adler-32 trailer
	if _, err := InflateDeflate(enc); err == nil {
		t.Fatal("accepted a zlib body with a bad checksum")
	}
}

type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// The stream reader must not touch the body until the caller reads, so setting
// up a streaming response does not block on, or consume, the network.
func TestDeflateReaderIsLazy(t *testing.T) {
	src := &countingReader{r: bytes.NewReader(zlibOf(t, body))}
	r := NewDeflateReader(src)
	if src.reads != 0 {
		t.Fatalf("constructing the reader read the body %d times", src.reads)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("streamed decode: %d bytes, %v", len(got), err)
	}
	r.Close()
}

// Streaming through a body that arrives a few bytes at a time decodes the same.
func TestDeflateReaderHandlesShortReads(t *testing.T) {
	for _, enc := range [][]byte{zlibOf(t, body), rawOf(t, body)} {
		r := NewDeflateReader(&oneByteReader{bytes.NewReader(enc)})
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("short reads: %d bytes, %v", len(got), err)
		}
	}
}

type oneByteReader struct{ r io.Reader }

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

// A deflate stream that arrives slowly must be decoded as it arrives. The
// framing used to be decided on a full 128-byte prefix, so the first bytes of a
// server-sent event stream sat in the reader until 128 compressed bytes had
// built up. Here one flushed message, far under 128 bytes, arrives and then the
// source stalls; the message must come out while it does.
func TestDeflateReaderDoesNotWaitForTheSniffLimit(t *testing.T) {
	for _, framing := range []string{"zlib", "raw"} {
		pr, pw := io.Pipe()
		release := make(chan struct{})
		go func() {
			var w interface {
				io.Writer
				Flush() error
				Close() error
			}
			if framing == "zlib" {
				w = zlib.NewWriter(pw)
			} else {
				w, _ = flate.NewWriter(pw, flate.DefaultCompression)
			}
			w.Write([]byte("data: tick\n\n"))
			w.Flush()
			<-release
			w.Close()
			pw.Close()
		}()

		r := NewDeflateReader(pr)
		got := make(chan string, 1)
		go func() {
			buf := make([]byte, 64)
			n, _ := r.Read(buf)
			got <- string(buf[:n])
		}()
		select {
		case s := <-got:
			if s != "data: tick\n\n" {
				t.Errorf("%s: first read %q", framing, s)
			}
			close(release)
		case <-time.After(2 * time.Second):
			t.Errorf("%s: the first message did not come out while the stream was stalled", framing)
			close(release)
			<-got // the read finishes once the stream does; never share r with it
		}
		io.Copy(io.Discard, r)
		r.Close()
	}
}
