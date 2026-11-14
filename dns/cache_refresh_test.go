package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A host whose connection is in use is looked up again in the background before
// its entry expires, so that a new connection to it (the old one died, a
// burst needs another) is never held on the resolver. An entry used to be
// looked up again only once it had expired, by the dial that needed it, which
// waited for the resolver: up to 15 s when the resolver stalls.
func TestAHostInUseIsLookedUpAheadOfItsExpiry(t *testing.T) {
	c := NewCache()
	c.SetTTL(5 * time.Second)
	var lookups atomic.Int32
	c.lookupHook = func(ctx context.Context, host string) ([]net.IP, error) {
		if lookups.Add(1) > 1 {
			// The resolver has become slow.
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []net.IP{net.IPv4(192, 0, 2, 1)}, nil
	}
	ctx := context.Background()
	if _, err := c.Resolve(ctx, "shop.example"); err != nil {
		t.Fatal(err)
	}

	// Used before 80% of its lifetime: nothing to do.
	c.KeepFresh("shop.example")
	time.Sleep(50 * time.Millisecond)
	if n := lookups.Load(); n != 1 {
		t.Fatalf("%d lookups for an entry in the first part of its life, want 1", n)
	}

	// Used past 80% of it: looked up again in the background.
	time.Sleep(4100 * time.Millisecond)
	c.KeepFresh("shop.example")
	time.Sleep(2500 * time.Millisecond) // the slow lookup is done; the old entry has expired
	if n := lookups.Load(); n != 2 {
		t.Fatalf("%d lookups, want 2: the entry was not refreshed ahead", n)
	}
	start := time.Now()
	if _, err := c.Resolve(ctx, "shop.example"); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("the dial after the old entry expired waited %v for the resolver", took)
	}
}

// A host nobody has looked up is not looked up for being kept fresh.
func TestKeepFreshLooksUpNothingNew(t *testing.T) {
	c := NewCache()
	var lookups atomic.Int32
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.IPv4(192, 0, 2, 1)}, nil
	}
	c.KeepFresh("never.example")
	time.Sleep(50 * time.Millisecond)
	if n := lookups.Load(); n != 0 {
		t.Fatalf("%d lookups for a host never resolved", n)
	}
}
