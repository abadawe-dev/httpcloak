// Package compress holds content-coding decoders shared by the transport and
// client packages, so a decoding rule lives in one place instead of in each
// request path.
package compress

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"errors"
	"io"
)

// sniffLimit is how much of a deflate body is examined before the framing is
// decided, matching kMaxZlibHeaderSniffBytes in Chromium's GzipSourceStream.
const sniffLimit = 128

// NewDeflateReader decodes a body sent with Content-Encoding: deflate.
//
// RFC 9110 section 8.4.1.2 defines that coding as the zlib format of RFC 1950,
// a two-byte header and an Adler-32 trailer around a raw RFC 1951 stream. Many
// servers send the raw stream instead, and browsers accept both, so servers get
// away with either. Every deflate path here used flate.NewReader, which reads
// raw only, so a body in the framing the RFC actually specifies failed to
// decode (#115).
//
// The choice between the two follows Chromium, net/filter/gzip_source_stream.cc:
// it inflates as zlib, and if that fails before producing any output and
// within the first 128 bytes, it restarts the body as raw deflate. A body whose
// zlib header is valid but whose data is corrupt after that point fails, as it
// does in Chrome.
//
// Nothing is read from r until the first Read, so a streaming body is not
// consumed before the caller asks for it. Close releases the decoder; it does
// not close r, which stays with its owner.
func NewDeflateReader(r io.Reader) io.ReadCloser {
	return &deflateReader{src: r}
}

// InflateDeflate decodes a whole deflate body. See NewDeflateReader.
func InflateDeflate(data []byte) ([]byte, error) {
	r := NewDeflateReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}

type deflateReader struct {
	src     io.Reader
	dec     io.ReadCloser
	err     error
	started bool
}

func (d *deflateReader) Read(p []byte) (int, error) {
	if !d.started {
		d.started = true
		d.dec, d.err = choose(d.src)
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.dec.Read(p)
}

func (d *deflateReader) Close() error {
	if d.dec != nil {
		return d.dec.Close()
	}
	return nil
}

// choose reads up to sniffLimit bytes, decides the framing on them, and
// returns a decoder over those bytes followed by the rest of src.
func choose(src io.Reader) (io.ReadCloser, error) {
	prefix := make([]byte, sniffLimit)
	n, err := io.ReadFull(src, prefix)
	prefix = prefix[:n]
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		// An empty body decodes to nothing, under either framing.
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	whole := io.MultiReader(bytes.NewReader(prefix), src)
	if looksLikeZlib(prefix) {
		return zlib.NewReader(whole)
	}
	return flate.NewReader(whole), nil
}

// looksLikeZlib reports whether inflating prefix as zlib succeeds as far as
// prefix goes: either it produces output, reaches the end of the stream, or
// runs out of input. Any other error is what makes Chrome fall back to raw.
func looksLikeZlib(prefix []byte) bool {
	zr, err := zlib.NewReader(bytes.NewReader(prefix))
	if err != nil {
		// A bad header, a preset dictionary, or a body shorter than a header.
		return false
	}
	defer zr.Close()
	var one [1]byte
	n, err := zr.Read(one[:])
	switch {
	case n > 0:
		return true
	case err == nil, errors.Is(err, io.EOF):
		return true
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Valid so far and wants more input, which is the rest of the body.
		return true
	default:
		return false
	}
}
