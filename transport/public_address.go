package transport

import (
	"fmt"
	"net"
	"net/netip"
)

// LocalAddressError is a direct connection that was not made because the
// address it would have gone to is not on the public internet, and the
// transport connects to public addresses only (TransportConfig's
// PublicAddressesOnly). Nothing was sent.
type LocalAddressError struct {
	// Addr is the address the request's host resolved to, or the host itself
	// when it is an IP literal.
	Addr netip.Addr
}

func (e *LocalAddressError) Error() string {
	return fmt.Sprintf("not connecting to %s: it is not a public address, and this session connects to public addresses only", e.Addr)
}

// checkPublic refuses ip, the address a direct connection is about to be made
// to, when the transport connects to public addresses only and ip is not one.
// It runs on each address as it is dialled, after the DNS cache, so what it
// checks is what the connection goes to: a name that resolves to this machine
// or its network is refused however it was looked up, and an answer that
// changes between lookups changes nothing. Connections to a proxy are not
// checked: the proxy resolves the request's host on its own network.
func checkPublic(publicOnly bool, ip net.IP) error {
	if !publicOnly {
		return nil
	}
	// A resolved or parsed address is always 4 or 16 bytes; anything else
	// leaves addr invalid, which isPublic refuses.
	addr, _ := netip.AddrFromSlice(ip)
	if isPublic(addr) {
		return nil
	}
	return &LocalAddressError{Addr: addr.Unmap()}
}

// notPublic are the address ranges outside the public internet that netip has
// no method for: "this network" (0.0.0.0/8, which Linux connects to this
// machine), shared address space for carrier-grade NAT (RFC 6598) and the
// limited broadcast address.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// isPublic reports whether addr is on the public internet: not this machine
// (loopback, unspecified), not a private network (RFC 1918, IPv6 unique local
// fc00::/7, RFC 6598 shared space), not link-local, broadcast or multicast,
// and not one of those spelled as an IPv4-mapped (::ffff:a.b.c.d) or
// IPv4-compatible (::a.b.c.d) IPv6 address. These are the addresses Chrome's
// Local Network Access keeps a public page from reaching.
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is6() {
		// An IPv4-compatible address (RFC 4291 2.5.5.1, deprecated) embeds an
		// IPv4 address in its last 32 bits; ::1 and :: are judged as the
		// "this network" addresses they embed, which are refused too.
		if b := addr.As16(); [12]byte(b[:12]) == [12]byte{} {
			addr = netip.AddrFrom4([4]byte(b[12:]))
		}
	}
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range notPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
