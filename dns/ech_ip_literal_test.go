package dns

import (
	"context"
	"testing"
	"time"
)

// An IP literal has no HTTPS record. Looking one up sent the address to a
// public resolver and cost 200 to 600ms on the first dial to each address;
// it must return at once with no config.
func TestNoECHLookupForIPLiterals(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "::1", "[::1]", "203.0.113.7"} {
		start := time.Now()
		cfg, err := FetchECHConfigs(context.Background(), h)
		if err != nil || cfg != nil {
			t.Errorf("%s: configs %v, err %v; want none", h, cfg, err)
		}
		if d := time.Since(start); d > 20*time.Millisecond {
			t.Errorf("%s took %v; an IP literal must not reach a resolver", h, d)
		}
	}
}
