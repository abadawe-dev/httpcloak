//go:build hctest

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Issue #114. Host callbacks used to run on whichever Go thread finished the
// work. A .NET host treats a thread that has run its code as one of its own
// and later sends it GC-suspension APCs; delivered while the thread runs Go
// code on a goroutine stack, they end the process with 0xC000000D. Every host
// callback now runs on a thread the shim created, which can be checked here
// even though the crash itself is Windows-only.
//
// Run with: go test -tags hctest -run Callback .
func TestHostCallbacksRunOnShimThreads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-155-windows","timeout":10}`)
	if h <= 0 {
		t.Fatalf("session_new returned %d", h)
	}
	defer hcTestSessionFree(h)

	const n = 20
	for i := 0; i < n; i++ {
		id := hcTestRegisterAsync()
		hcTestRequestAsync(h, fmt.Sprintf(`{"method":"GET","url":%q}`, srv.URL), id)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		calls, onWorker, _, _ := hcTestCounts()
		if calls >= n {
			if onWorker != calls {
				t.Errorf("%d of %d async callbacks ran on a Go thread", calls-onWorker, calls)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d async callbacks arrived", calls, n)
		}
		time.Sleep(20 * time.Millisecond)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); hcTestCacheGet(false) }()
	}
	wg.Wait()
	_, _, gets, getsOnWorker := hcTestCounts()
	if gets != 16 || getsOnWorker != gets {
		t.Errorf("sync cache callbacks: %d calls, %d on shim threads; want 16 and 16", gets, getsOnWorker)
	}
}

// A callback that re-enters the library and triggers another callback must
// not wait behind itself: the pool keeps a free worker for every queued job.
func TestReentrantCallbackDoesNotDeadlock(t *testing.T) {
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); hcTestCacheGet(true) }()
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("re-entrant callbacks deadlocked")
	}
}
