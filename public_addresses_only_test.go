package httpcloak

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/transport"
)

// WithPublicAddressesOnly reaches the transports a session builds: its own,
// its forks', and those it builds again when its proxy changes. Each refuses
// a name that resolves to this machine, before connecting.
func TestPublicAddressesOnlyHoldsForTheSessionItsForksAndANewProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	url := "http://localhost:" + port + "/"

	refused := func(t *testing.T, s *Session) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := s.Get(ctx, url)
		if err == nil {
			resp.Close()
			t.Fatal("a name that resolves to this machine was connected to")
		}
		var local *transport.LocalAddressError
		if !errors.As(err, &local) || !transport.RequestNotSent(err) {
			t.Fatalf("got %v, want a LocalAddressError, not sent", err)
		}
	}

	s := NewSession("chrome-latest", WithPublicAddressesOnly())
	defer s.Close()
	refused(t, s)

	fork := s.Fork(1)[0]
	defer fork.Close()
	refused(t, fork)

	s.SetProxy("http://127.0.0.1:1")
	s.SetProxy("")
	refused(t, s)

	plain := NewSession("chrome-latest")
	defer plain.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := plain.Get(ctx, url)
	if err != nil {
		t.Fatalf("without the option the local server answers: %v", err)
	}
	resp.Close()
}
