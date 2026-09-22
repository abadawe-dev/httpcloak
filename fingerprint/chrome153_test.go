package fingerprint

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Chrome 153 is a headers-only bump over 152, and the first release on
// Chrome's two-week cadence. Everything below the header block is inherited
// through based_on, so these tests are mostly about what must NOT have moved.

const chrome153SecCHUA = `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`

// The desktop and Android presets carry the new User-Agent and the reseeded
// brand list, and nothing else.
func TestChrome153Desktop(t *testing.T) {
	for _, name := range []string{
		"chrome-153", "chrome-153-windows", "chrome-153-linux",
		"chrome-153-macos", "chrome-153-android",
	} {
		p := Get(name)
		if p == nil {
			t.Errorf("%s not registered", name)
			continue
		}
		if !strings.Contains(p.UserAgent, "Chrome/153.0.0.0") {
			t.Errorf("%s: UA = %q, want Chrome/153.0.0.0; the based_on chain may "+
				"have fallen back to 152", name, p.UserAgent)
		}
		if got := chrome152SecCHUA(p); got != chrome153SecCHUA {
			t.Errorf("%s: sec-ch-ua = %q, want %q", name, got, chrome153SecCHUA)
		}
	}
}

// A headers-only bump has to leave the ClientHello alone, and "alone" here
// means the 152 values reached 153 through based_on rather than being dropped.
// A JSON that forgot to inherit would still load and still send the right
// headers, so nothing but this comparison would notice.
func TestChrome153InheritsTheChrome152ClientHello(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos", "android"} {
		old := Get("chrome-152-" + plat)
		new := Get("chrome-153-" + plat)
		if old == nil || new == nil {
			t.Fatalf("chrome-15{2,3}-%s: one of the pair is not registered", plat)
		}
		if old.ClientHelloID != new.ClientHelloID {
			t.Errorf("chrome-153-%s: ClientHelloID = %v, want 152's %v",
				plat, new.ClientHelloID, old.ClientHelloID)
		}
		if old.QUICClientHelloID != new.QUICClientHelloID {
			t.Errorf("chrome-153-%s: QUICClientHelloID = %v, want 152's %v",
				plat, new.QUICClientHelloID, old.QUICClientHelloID)
		}
		// The two wire changes 152 introduced: one GREASE value at the head of
		// signature_algorithms, and the trust_anchors list.
		if len(new.SignatureAlgorithms) != len(old.SignatureAlgorithms) {
			t.Errorf("chrome-153-%s: %d signature algorithms, want 152's %d; the "+
				"tls block did not inherit", plat, len(new.SignatureAlgorithms), len(old.SignatureAlgorithms))
		} else {
			for i := range old.SignatureAlgorithms {
				if old.SignatureAlgorithms[i] != new.SignatureAlgorithms[i] {
					t.Errorf("chrome-153-%s: signature algorithm %d = %#04x, want 152's %#04x",
						plat, i, new.SignatureAlgorithms[i], old.SignatureAlgorithms[i])
				}
			}
		}
		if len(new.TrustAnchors) != len(old.TrustAnchors) {
			t.Errorf("chrome-153-%s: %d trust anchors, want 152's %d",
				plat, len(new.TrustAnchors), len(old.TrustAnchors))
		} else {
			for i := range old.TrustAnchors {
				if !bytes.Equal(old.TrustAnchors[i], new.TrustAnchors[i]) {
					t.Errorf("chrome-153-%s: trust anchor %d differs from 152's", plat, i)
				}
			}
		}
		// Only two header values may move.
		if diff := headerValueDiff(old, new); len(diff) != 2 {
			t.Errorf("chrome-153-%s: %d header values differ from 152, want 2 "+
				"(user-agent and sec-ch-ua): %v", plat, len(diff), diff)
		}
	}
}

// headerValueDiff names the header keys whose value differs between two
// presets, comparing the ordered lists so a reordering shows up too.
func headerValueDiff(a, b *Preset) []string {
	var diff []string
	if a.UserAgent != b.UserAgent {
		diff = append(diff, "user-agent")
	}
	if len(a.HeaderOrder) != len(b.HeaderOrder) {
		return append(diff, fmt.Sprintf("header count %d vs %d", len(a.HeaderOrder), len(b.HeaderOrder)))
	}
	for i := range a.HeaderOrder {
		if a.HeaderOrder[i].Key != b.HeaderOrder[i].Key {
			diff = append(diff, fmt.Sprintf("order %d: %s vs %s", i, a.HeaderOrder[i].Key, b.HeaderOrder[i].Key))
			continue
		}
		if a.HeaderOrder[i].Value != b.HeaderOrder[i].Value {
			diff = append(diff, a.HeaderOrder[i].Key)
		}
	}
	return diff
}

// The greased brand list is not a capture, it is a function of the major
// version, so it can be derived instead of guessed. This replays Chromium's
// derivation over every version the tree already carries: if the algorithm
// below matches all of those, the 153 value it produces is right too, and if
// Chrome ever changes the algorithm this fails on the old versions first.
//
// From components/embedder_support/user_agent_utils.cc:
// GetGreasedUserAgentBrandVersion picks two punctuation characters out of
// greasey_chars by the major version, takes the GREASE version out of
// {"8","99","24"}, and GenerateBrandVersionList orders the three brands by one
// of six permutations, all seeded on the same number.
func TestChrome153BrandListFollowsChromium(t *testing.T) {
	for major := 146; major <= 152; major++ {
		p := GetStrict(fmt.Sprintf("chrome-%d-windows", major))
		if p == nil {
			continue
		}
		want := chrome152SecCHUA(p)
		if got := greasedBrandList(major); got != want {
			t.Errorf("chrome-%d: derivation gives %q, tree has %q", major, got, want)
		}
	}
	if got := greasedBrandList(153); got != chrome153SecCHUA {
		t.Errorf("chrome-153: derivation gives %q, preset has %q", got, chrome153SecCHUA)
	}
}

func greasedBrandList(major int) string {
	chars := []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	versions := []string{"8", "99", "24"}
	orders := [6][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}

	greasey := fmt.Sprintf("Not%sA%sBrand", chars[major%len(chars)], chars[(major+1)%len(chars)])
	brands := [3][2]string{
		{greasey, versions[major%len(versions)]},
		{"Chromium", fmt.Sprint(major)},
		{"Google Chrome", fmt.Sprint(major)},
	}
	var slots [3]string
	for i, pos := range orders[major%len(orders)] {
		slots[pos] = fmt.Sprintf("%q;v=%q", brands[i][0], brands[i][1])
	}
	return strings.Join(slots[:], ", ")
}

// chrome-latest is what a caller gets when they ask for "whatever Chrome is
// now", so it has to move with the newest desktop preset.
func TestChromeLatestIsChrome153(t *testing.T) {
	latest := Get("chrome-latest")
	if latest == nil {
		t.Fatal("chrome-latest not registered")
	}
	if !strings.Contains(latest.UserAgent, "Chrome/153.0.0.0") {
		t.Errorf("chrome-latest UA = %q, want Chrome/153.0.0.0", latest.UserAgent)
	}
}

// There is no chrome-153-ios, on purpose. The CriOS User-Agent carries a build
// number no rule derives from the major version, so an iOS preset is only as
// new as its last capture. Registering the name with 152's User-Agent behind it
// would be a silently wrong fingerprint, which is worse than a missing preset:
// nothing fails, the requests go out, and the UA names a browser build that
// never existed alongside that TLS handshake.
//
// Delete this test in the same commit that adds a captured chrome-153-ios.
func TestChrome153HasNoIOSPresetYet(t *testing.T) {
	if p := GetStrict("chrome-153-ios"); p != nil {
		t.Errorf("chrome-153-ios is registered with UA %q; if that build number "+
			"came from a capture, delete this test, and if it did not, drop the "+
			"preset", p.UserAgent)
	}
	newest := GetStrict("chrome-152-ios")
	if newest == nil {
		t.Fatal("chrome-152-ios should still be the newest iOS preset")
	}
	if !strings.Contains(newest.UserAgent, "CriOS/152.") {
		t.Errorf("chrome-152-ios UA = %q, want a CriOS/152 build", newest.UserAgent)
	}
}

// The -latest aliases move as a set, apart from iOS. Android's User-Agent is
// the reduced one, so it carries no build number and follows desktop; iOS does
// carry one and stays where its last capture put it.
//
// This is the single home for the alias assertion. Each version bump used to
// leave a copy behind in the previous version's file, all pinned to the same
// values; the 151 file's copy was folded in here. Move this test to the next
// version's file rather than adding another.
func TestChrome153LatestAliases(t *testing.T) {
	for _, tc := range []struct{ alias, wantUA string }{
		{"chrome-latest", "Chrome/153.0.0.0"},
		{"chrome-latest-windows", "Chrome/153.0.0.0"},
		{"chrome-latest-linux", "Chrome/153.0.0.0"},
		{"chrome-latest-macos", "Chrome/153.0.0.0"},
		{"chrome-latest-android", "Chrome/153.0.0.0"},
		{"chrome-latest-ios", "CriOS/152.0.7977.64"},
	} {
		p := GetStrict(tc.alias)
		if p == nil {
			t.Errorf("%s not registered", tc.alias)
			continue
		}
		if !strings.Contains(p.UserAgent, tc.wantUA) {
			t.Errorf("%s: UA = %q, want it to contain %q", tc.alias, p.UserAgent, tc.wantUA)
		}
	}
}
