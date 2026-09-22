package fingerprint

import (
	"encoding/hex"
	"sort"
	"testing"

	utls "github.com/sardanioss/utls"
)

// chromeTrustAnchorOrder is the trust_anchors (0xCA34) list as a real Chrome
// sends it: the 28 identifiers in ascending byte order. Taken from a Windows
// Chrome 154 profile in everyday use, hitting a public echo endpoint.
//
// Pinned verbatim rather than derived with a sort, so the test still says what
// Chrome sent if the set ever changes.
//
// Do not replace it with a capture from a headless browser on a fresh
// --user-data-dir. Those gave different, unsorted orders, and Chrome for
// Testing gave yet another for the same version. Such profiles exit before the
// component updater delivers the root store, so they do not show what a real
// user's browser sends.
var chromeTrustAnchorOrder = []string{
	"82df130201", "82df130206", "82df13020d", "82df13020e", "82df13020f",
	"82df130212", "82df130213", "82df130214",
	"839a648c9b2d0107", "839a648c9b2d0108", "839a648c9b2d0109", "839a648c9b2d010a",
	"839a648c9b2d010b", "839a648c9b2d010c", "839a648c9b2d010d", "839a648c9b2d0112",
	"839a648c9b2d0113",
	"d6790901", "d6790904", "d6790905", "d6790906", "d6790907", "d6790908",
	"d679090a", "d679090b", "d679090c", "d679090d", "d679090f",
}

// TestTrustAnchorsAreNotShuffled locks the exact line that caused the bug.
//
// Chrome holds this list constant: 29 connections spanning three separate
// processes with fresh profiles produced one byte-identical payload, while the
// same 29 connections produced 29 different extension orders. We used to
// permute the list on every handshake, which made two connections from one
// session trivially linkable with no statistics at all.
func TestTrustAnchorsAreNotShuffled(t *testing.T) {
	anchors := [][]byte{{0x01}, {0x02}, {0x03}}
	var exts []utls.TLSExtension
	ApplyTrustAnchors(&exts, anchors)

	for _, e := range exts {
		ta, ok := e.(*utls.TrustAnchorsExtension)
		if !ok {
			continue
		}
		if ta.Shuffle {
			t.Fatal("trust_anchors is set to shuffle per connection; Chrome sends " +
				"this list in one fixed order and never varies it, so shuffling " +
				"makes two connections from one session linkable")
		}
		return
	}
	t.Fatal("ApplyTrustAnchors did not add a trust_anchors extension")
}

// TestTrustAnchorOrderMatchesChrome locks the stored order to what Chrome
// sends, which is sorted. Turning the shuffle off only helps if the fixed order
// is the real one: a stable list in the wrong order is as visible as a moving
// one, just across clients instead of across connections.
func TestTrustAnchorOrderMatchesChrome(t *testing.T) {
	for _, name := range []string{
		"chrome-152-windows", "chrome-152-linux", "chrome-152-macos", "chrome-152-android",
		"chrome-153-windows", "chrome-153-linux", "chrome-153-macos", "chrome-153-android",
	} {
		p := Get(name)
		if p == nil {
			t.Fatalf("%s: preset missing", name)
		}
		if len(p.TrustAnchors) == 0 {
			t.Fatalf("%s: no trust anchors", name)
		}
		got := make([]string, len(p.TrustAnchors))
		for i, a := range p.TrustAnchors {
			got[i] = hex.EncodeToString(a)
		}
		if len(got) != len(chromeTrustAnchorOrder) {
			t.Errorf("%s: %d anchors, Chrome sends %d", name, len(got), len(chromeTrustAnchorOrder))
			continue
		}
		for i := range got {
			if got[i] != chromeTrustAnchorOrder[i] {
				t.Errorf("%s: anchor %d is %s, Chrome sends %s\n"+
					"  Chrome sends the anchors in ascending byte order",
					name, i, got[i], chromeTrustAnchorOrder[i])
				break
			}
		}
		if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }) {
			t.Errorf("%s: anchor list is not sorted; Chrome sends it in ascending byte order", name)
		}
	}
}

// TestQUICTrustAnchorsArePermuted is the counterpart to
// TestTrustAnchorsAreNotShuffled. The two transports really do differ, and a
// single "correct" answer for both is wrong either way round.
//
// Chrome 153.0.8010.52, same 28 identifiers on both transports:
//
//	TCP   29 connections over 3 processes -> 1 trust_anchors payload
//	QUIC   3 connections in ONE process   -> 3 trust_anchors payloads
func TestQUICTrustAnchorsArePermuted(t *testing.T) {
	anchors := [][]byte{{0x01}, {0x02}, {0x03}}
	var exts []utls.TLSExtension
	ApplyTrustAnchorsPermuted(&exts, anchors)

	for _, e := range exts {
		ta, ok := e.(*utls.TrustAnchorsExtension)
		if !ok {
			continue
		}
		if !ta.Shuffle {
			t.Fatal("QUIC trust_anchors is pinned to one order; Chrome reshuffles " +
				"the list on every QUIC connection, so a fixed order is as " +
				"distinguishable there as a shuffled one is on TCP")
		}
		return
	}
	t.Fatal("ApplyTrustAnchorsPermuted did not add a trust_anchors extension")
}
