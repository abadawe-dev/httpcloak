package fingerprint

import (
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	utls "github.com/sardanioss/utls"
)

// What Chrome does with trust_anchors (0xCA34) depends on the version, and every
// row below was checked against Chromium source and against the wire:
//
//	              list order                list on QUIC         extension position
//	152, 153      fixed, hash-set order     reshuffled per conn  permuted
//	154, 155      sorted                    sorted, fixed        permuted
//
// 152 and 153 hold the classic IDs in an absl::flat_hash_set and encode them in
// its iteration order (net/ssl/ssl_config_service.cc, SelectAllTrustAnchorIDs),
// which is fixed for a build and has no meaning. 154 sorts them first
// (net/cert/x509_util.cc, EncodeTlsRequestedTrustAnchorIDList, Chromium commit
// 942bda4298c1). Measured: 153.0.8010.52 sent one payload over 29 TCP
// connections in three processes and three different ones over three QUIC
// connections; 155.0.8059.39 sent one sorted payload over three QUIC
// connections, and real Windows Chrome 154 and 155 profiles sent it sorted over
// TCP.

// chrome153TrustAnchorOrder is the list exactly as Google Chrome 153.0.8010.52
// sends it over TCP. It has no structure to derive, so it is pinned verbatim.
var chrome153TrustAnchorOrder = []string{
	"d6790901", "839a648c9b2d0108", "82df130201", "82df13020e", "82df130214",
	"82df13020d", "839a648c9b2d010c", "d6790904", "839a648c9b2d0109", "d6790908",
	"839a648c9b2d0107", "d679090c", "839a648c9b2d010d", "d679090b", "839a648c9b2d010a",
	"839a648c9b2d0113", "d679090f", "839a648c9b2d010b", "d679090d", "82df130213",
	"d6790905", "839a648c9b2d0112", "82df130206", "d6790906", "82df13020f",
	"82df130212", "d679090a", "d6790907",
}

func anchorHex(p *Preset) []string {
	out := make([]string, len(p.TrustAnchors))
	for i, a := range p.TrustAnchors {
		out[i] = hex.EncodeToString(a)
	}
	return out
}

// TestTrustAnchorOrderFollowsTheVersion locks the stored list per version.
func TestTrustAnchorOrderFollowsTheVersion(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos", "android"} {
		for _, v := range []int{152, 153} {
			name := fmt.Sprintf("chrome-%d-%s", v, plat)
			got := anchorHex(Get(name))
			if fmt.Sprint(got) != fmt.Sprint(chrome153TrustAnchorOrder) {
				t.Errorf("%s: anchor list is not the order Chrome %d sends\n got: %v", name, v, got)
			}
			if sort.StringsAreSorted(got) {
				t.Errorf("%s: anchor list is sorted, but Chrome only sorts it from 154", name)
			}
		}
		for _, v := range []int{154, 155} {
			name := fmt.Sprintf("chrome-%d-%s", v, plat)
			got := anchorHex(Get(name))
			if len(got) != len(chrome153TrustAnchorOrder) {
				t.Errorf("%s: %d anchors, want %d", name, len(got), len(chrome153TrustAnchorOrder))
			}
			if !sort.StringsAreSorted(got) {
				t.Errorf("%s: anchor list is not sorted; Chrome sorts it from 154", name)
			}
		}
	}
}

// TestQUICTrustAnchorShuffleFollowsTheVersion locks the per-version QUIC flag.
func TestQUICTrustAnchorShuffleFollowsTheVersion(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos", "android"} {
		for v, want := range map[int]bool{152: true, 153: true, 154: false, 155: false} {
			name := fmt.Sprintf("chrome-%d-%s", v, plat)
			if got := Get(name).QUICTrustAnchorShuffle; got != want {
				t.Errorf("%s: QUICTrustAnchorShuffle = %v, want %v", name, got, want)
			}
		}
	}
}

// TestTCPTrustAnchorListIsNeverShuffled: on TCP the list is fixed on every
// version. The extension used to reshuffle it per connection, which made two
// connections from one session linkable by comparing the extension body.
func TestTCPTrustAnchorListIsNeverShuffled(t *testing.T) {
	var exts []utls.TLSExtension
	ApplyTrustAnchors(&exts, [][]byte{{1}, {2}, {3}})
	ta := findTA(t, exts)
	if ta.Shuffle {
		t.Fatal("TCP trust_anchors list is set to shuffle per connection")
	}
}

// TestQUICTrustAnchorsFollowThePreset: the QUIC helper honours the flag both
// ways, since either fixed choice is wrong for some version.
func TestQUICTrustAnchorsFollowThePreset(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{{"chrome-153-windows", true}, {"chrome-155-windows", false}} {
		var exts []utls.TLSExtension
		ApplyQUICTrustAnchors(&exts, Get(tc.name))
		if got := findTA(t, exts).Shuffle; got != tc.want {
			t.Errorf("%s: QUIC list shuffle = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestTrustAnchorsPositionIsPermuted: the extension moves with the rest of the
// permutation on both transports. It used to be inserted after the shuffle,
// always in the slot ahead of the pinned tail, while Chrome moved it (155 put
// it at 9, 12 and 11 of 12 on three QUIC connections).
func TestTrustAnchorsPositionIsPermuted(t *testing.T) {
	p := Get("chrome-155-windows")
	tcp, quic := map[int]bool{}, map[int]bool{}
	for i := 0; i < 64; i++ {
		s, _, err := ResolveClientHelloSpec(p, "", nil, false, 1)
		if err != nil {
			t.Fatal(err)
		}
		ApplyTrustAnchors(&s.Extensions, p.TrustAnchors)
		tcp[taIndex(t, s.Extensions)] = true

		q, _, err := ResolveQUICClientHelloSpec(p, false, 1)
		if err != nil {
			t.Fatal(err)
		}
		quic[taIndex(t, q.Extensions)] = true
	}
	if len(tcp) < 4 {
		t.Errorf("TCP: trust_anchors took only %d positions over 64 hellos; it is not being permuted", len(tcp))
	}
	if len(quic) < 4 {
		t.Errorf("QUIC: trust_anchors took only %d positions over 64 hellos; it is not being permuted", len(quic))
	}
}

func findTA(t *testing.T, exts []utls.TLSExtension) *utls.TrustAnchorsExtension {
	t.Helper()
	for _, e := range exts {
		if ta, ok := e.(*utls.TrustAnchorsExtension); ok {
			return ta
		}
	}
	t.Fatal("no trust_anchors extension")
	return nil
}

func taIndex(t *testing.T, exts []utls.TLSExtension) int {
	t.Helper()
	for i, e := range exts {
		if _, ok := e.(*utls.TrustAnchorsExtension); ok {
			return i
		}
	}
	t.Fatal("no trust_anchors extension")
	return -1
}
