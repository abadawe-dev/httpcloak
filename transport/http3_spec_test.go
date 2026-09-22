package transport

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

// The H3 transport regenerates the ClientHelloSpec per dial (the fix for the
// concurrent-dial data race: utls ApplyPreset mutates the spec in place, so a
// shared cached spec races under concurrency). This regression test locks the
// three properties that fix depends on:
//
//  1. each call returns a DISTINCT spec object (structural race-safety: no two
//     concurrent dials ever hold the same mutable spec),
//  2. the extension ORDER varies between calls, because Chrome redraws its
//     permutation on every handshake, and
//  3. the extension SET and the cipher-suite order do NOT vary, because those
//     are fixed properties of the profile.
//
// Property 2 used to be asserted the other way round, requiring a byte-identical
// extension order across calls "so JA3/JA4 stay stable between connections of one
// session". That is not what Chrome does. BoringSSL keeps extension_permutation
// on SSL_HANDSHAKE rather than on SSL_CTX, so the order is redrawn per
// connection. Measured on Chrome 153.0.8010.52: one browser session opening 7
// parallel connections produced 7 different orders, and 3 QUIC connections from
// one process produced 3. Holding one order per session made two connections
// from one session linkable by comparing extension sequences, with no statistics
// needed.
func TestH3SpecRegenDeterministic(t *testing.T) {
	tr, err := NewHTTP3Transport(fingerprint.Chrome146(), dns.NewCache())
	if err != nil {
		t.Fatalf("NewHTTP3Transport: %v", err)
	}

	const n = 8
	specs := make([]*utls.ClientHelloSpec, 0, n)
	for i := 0; i < n; i++ {
		s := tr.getSpecForHost("example.com")
		if s == nil {
			t.Fatal("getSpecForHost returned nil")
		}
		specs = append(specs, s)
	}

	// (1) distinct objects: a shared pointer would mean concurrent dials race.
	for i := range specs {
		for j := i + 1; j < len(specs); j++ {
			if specs[i] == specs[j] {
				t.Fatal("getSpecForHost returned the SAME spec pointer twice; concurrent dials would race-mutate it")
			}
		}
	}

	// (2) the extension order must move between connections.
	orders := map[string]int{}
	for _, sp := range specs {
		var b []string
		for _, e := range sp.Extensions {
			b = append(b, fmt.Sprintf("%T", e))
		}
		orders[strings.Join(b, "|")]++
	}
	if len(orders) == 1 {
		t.Fatalf("%d dials produced ONE extension order; the order is pinned for "+
			"the session, so every connection carries a byte-identical ClientHello "+
			"order. Chrome redraws the permutation on every handshake.", n)
	}

	// (3) the extension SET is fixed even though the order is not, and so is the
	// cipher-suite order. A permutation that added or dropped an extension, or
	// that reordered ciphers, would be a different bug wearing the same clothes.
	want := sortedTypes(specs[0].Extensions)
	for i, sp := range specs[1:] {
		got := sortedTypes(sp.Extensions)
		if len(got) != len(want) {
			t.Fatalf("dial %d: extension count drift: %d vs %d", i+1, len(got), len(want))
		}
		for k := range want {
			if got[k] != want[k] {
				t.Fatalf("dial %d: extension SET drift: %s vs %s", i+1, got[k], want[k])
			}
		}
		if len(sp.CipherSuites) != len(specs[0].CipherSuites) {
			t.Fatalf("dial %d: cipher count drift: %d vs %d", i+1, len(sp.CipherSuites), len(specs[0].CipherSuites))
		}
		for k := range sp.CipherSuites {
			if sp.CipherSuites[k] != specs[0].CipherSuites[k] {
				t.Fatalf("dial %d: cipher order drift at %d: %#x vs %#x; Chrome permutes "+
					"extensions, not cipher suites", i+1, k, sp.CipherSuites[k], specs[0].CipherSuites[k])
			}
		}
	}
}

func sortedTypes(exts []utls.TLSExtension) []string {
	out := make([]string, len(exts))
	for i, e := range exts {
		out[i] = fmt.Sprintf("%T", e)
	}
	sort.Strings(out)
	return out
}

// A TCP-only fingerprint source must not degrade the HTTP/3 hello.
//
// A preset carries one RawClientHello and one JA3, and which transport they
// describe is a property of the bytes: a QUIC hello carries
// quic_transport_parameters and a TCP hello does not. Building a preset from a
// TCP capture used to erase the QUIC identity it inherited, which left this
// transport with nothing to build from. getSpecForHost then returned nil and
// the QUIC stack quietly used its own default hello.
//
// Quietly is the problem. Measured against a live endpoint before the fix,
// chrome-151-windows over HTTP/3 gave q13d311_55b375c5d22e_653d80c3fe9d with 11
// extensions; the same preset with a TCP ja3 added gave
// q13d37_55b375c5d22e_4ca1098a2eeb with 7. Every request succeeded, so nothing
// reported it. Anyone running HTTP/3 with a custom fingerprint was affected.
//
// This asserts offline what that measurement showed: adding a TCP source leaves
// the HTTP/3 hello byte-identical to the base preset's.
func TestH3HelloSurvivesATCPOnlySource(t *testing.T) {
	base := fingerprint.Get("chrome-151-windows")
	if base == nil {
		t.Skip("chrome-151-windows unavailable")
	}

	// A TCP JA3, the shape a caller supplies when mirroring a TCP capture.
	spec := &fingerprint.PresetSpec{
		Name:    "h3-degrade-probe",
		BasedOn: "chrome-151-windows",
		TLS:     &fingerprint.TLSSpec{JA3: "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0"},
	}
	withJA3, err := fingerprint.BuildPreset(spec)
	if err != nil {
		t.Fatalf("BuildPreset: %v", err)
	}

	specOf := func(p *fingerprint.Preset, label string) []string {
		tr, err := NewHTTP3Transport(p, dns.NewCache())
		if err != nil {
			t.Fatalf("NewHTTP3Transport(%s): %v", label, err)
		}
		t.Cleanup(func() { _ = tr.Close() })
		s := tr.getSpecForHost("example.com")
		if s == nil {
			t.Fatalf("%s: getSpecForHost returned nil, so HTTP/3 would fall back "+
				"to the QUIC stack's default hello and carry no configured "+
				"fingerprint at all", label)
		}
		// Sorted, not in wire order: the QUIC hello permutes its extensions per
		// handshake the way Chromium does, so two transports legitimately differ
		// in order. What must not differ is WHICH extensions are present.
		names := make([]string, len(s.Extensions))
		for i, e := range s.Extensions {
			names[i] = fmt.Sprintf("%T", e)
		}
		sort.Strings(names)
		return names
	}

	want := specOf(base, "chrome-151-windows")
	got := specOf(withJA3, "chrome-151-windows + TCP ja3")

	if len(got) != len(want) {
		t.Fatalf("HTTP/3 hello lost extensions when a TCP ja3 was added: %d vs %d.\n"+
			"A TCP source says nothing about QUIC, so the QUIC identity must "+
			"survive it untouched.\n  base: %v\n  with ja3: %v",
			len(got), len(want), want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("HTTP/3 extension set differs after adding a TCP ja3: %s vs %s\n"+
				"  base: %v\n  with ja3: %v", want[i], got[i], want, got)
		}
	}
}
