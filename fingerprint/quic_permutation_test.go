package fingerprint

import (
	"fmt"
	"testing"
)

// TestQUICExtensionOrderIsRedrawnPerCall locks the H3 order-pinning fix.
//
// The QUIC path used to build its spec from a seed drawn once per transport,
// which meant every connection a session opened carried a byte-identical
// extension order. The TCP path hides that failure: its parrot literals already
// shuffle with fresh randomness when the spec is built, and the seeded shuffle
// runs on top, so the seed changes nothing there. The QUIC literals have no
// inline shuffle, so the seed was the only permutation and it never moved.
//
// Chrome redraws on every handshake, on both transports, because BoringSSL
// keeps extension_permutation on SSL_HANDSHAKE rather than on SSL_CTX.
// Measured on 153.0.8010.52: 7 parallel TCP connections in one browser session
// gave 7 different orders, and 3 QUIC connections from one process gave 3.
//
// The seed is passed deliberately fixed here: that is exactly the condition
// that used to pin the order, so if pinning ever returns this fails.
func TestQUICExtensionOrderIsRedrawnPerCall(t *testing.T) {
	p := Get("chrome-153-linux")
	if p == nil {
		t.Fatal("preset missing")
	}
	const pinnedSeed = int64(0x5eed5eed5eed5eed)

	seen := map[string]int{}
	const n = 8
	for i := 0; i < n; i++ {
		spec, _, err := ResolveQUICClientHelloSpec(p, false, pinnedSeed)
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		var order string
		for _, e := range spec.Extensions {
			order += fmt.Sprintf("%T|", e)
		}
		seen[order]++
	}
	if len(seen) == 1 {
		t.Fatalf("%d QUIC spec builds produced ONE extension order; the order is "+
			"pinned for the session, so every connection a session opens carries "+
			"a byte-identical ClientHello order. Chrome redraws per handshake.", n)
	}
	if len(seen) < n/2 {
		t.Errorf("%d builds produced only %d distinct orders, expected close to %d",
			n, len(seen), n)
	}
}

// TestTCPExtensionOrderIsRedrawnPerCall is the same property on the transport
// that was already correct, so a change that "fixes" one by breaking the other
// is caught.
func TestTCPExtensionOrderIsRedrawnPerCall(t *testing.T) {
	p := Get("chrome-153-linux")
	const pinnedSeed = int64(0x5eed5eed5eed5eed)

	seen := map[string]int{}
	const n = 8
	for i := 0; i < n; i++ {
		spec, _, err := ResolveClientHelloSpec(p, "", nil, false, pinnedSeed)
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		var order string
		for _, e := range spec.Extensions {
			order += fmt.Sprintf("%T|", e)
		}
		seen[order]++
	}
	if len(seen) == 1 {
		t.Fatalf("%d TCP spec builds produced ONE extension order", n)
	}
}
