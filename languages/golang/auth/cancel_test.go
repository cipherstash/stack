package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// A profile serves every strategy, and through them every encrypt client,
// in a process: a request cancelled while its token is fetched must fail
// on its own and leave the profile open for the next.

// tokenServer answers the access-key exchange, holding each request until
// the client gives up while hold is set.
func tokenServer(t *testing.T, hold *atomic.Bool) *httptest.Server {
	t.Helper()
	var jwt string
	// The server notices a client that hung up a moment after the client
	// has gone: it reads the closed connection on a goroutine of its own.
	// So the test's end waits for each held request to see its
	// cancellation, for a bounded time, before the server is closed (which
	// would end the request's context itself and hide a request the client
	// never cancelled).
	var held sync.WaitGroup
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hold.Load() {
			held.Add(1)
			defer held.Done()
			// The server notices a client that hung up only once the body
			// is read.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
				return
			case <-done:
			}
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
				t.Error("a held request was never cancelled")
			}
			return
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		close(done)
		held.Wait()
	})
	jwt = testJWT(t, server.URL)
	return server
}

func TestATokenFetchCancelledFailsOnlyItself(t *testing.T) {
	guestOrSkip(t)
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	hold.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Token: %v, want the deadline", err)
	}
	hold.Store(false)
	// The next Token waits for the abandoned one to finish.
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
	if profile.root.closed || profile.root.inst.module.IsClosed() {
		t.Fatal("the profile was closed")
	}
}

// An access-key exchange rotates nothing, so it ends with its caller: the
// held request is cancelled at the caller's deadline, not run on for the
// refresh grace, and Close does not wait for it.
func TestAnAccessKeyExchangeEndsWithItsCaller(t *testing.T) {
	guestOrSkip(t)
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}

	hold.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Token: %v, want the deadline", err)
	}
	// The grace is 10 seconds; a Close that waited for it would take that.
	start := time.Now()
	if err := strategy.Close(); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("Close took %v: the exchange ran on past its caller", waited)
	}
}

// A device session's refresh is the request that rotates a credential: the
// service answers with a new refresh token and retires the old one. A
// caller that gives up returns at once, but the refresh runs on, and what
// it brings is saved. The next Token is served from it with no second
// request, and the profile on disk holds the rotated refresh token.
func TestARefreshAnsweredAfterItsCallerGaveUpIsKept(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	var requests atomic.Int32
	answered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			// The old refresh token is retired once the service answers.
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(150 * time.Millisecond)
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
		close(answered)
	}))
	t.Cleanup(server.Close)
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Token: %v, want the deadline", err)
	}
	select {
	case <-answered:
		t.Fatal("the cancelled Token waited for the service's answer")
	default:
	}
	if token, err := strategy.Token(context.Background()); err != nil || token != "fresh" {
		t.Fatalf("the next Token: %q, %v, want the refreshed token", token, err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d refresh requests, want 1: the late answer was dropped", n)
	}
	data, err := os.ReadFile(filepath.Join(dir, "workspaces", wsA, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["refresh_token"] != "refresh-2" {
		t.Fatalf("stored refresh token = %v, want the rotated one", stored["refresh_token"])
	}
}

// A refresh runs on after its caller gives up, so the guest call under it
// can succeed after the caller's context ended. It still fails with the
// context's error; what the refresh brought is kept for the next call.
func TestARefreshThatSucceedsAfterItsContextEndsFailsWithIt(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
	}))
	t.Cleanup(server.Close)
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	out, err := strategy.store.callArgs(withRefresh(ctx), func(i *instance) api.Function { return i.authRefresh }, guest.BufArg([]byte(strategy.handle)))
	if !errors.Is(err, context.Canceled) || out != nil {
		t.Fatalf("refresh: %q, %v, want no token and context.Canceled", out, err)
	}
	if token, err := strategy.Token(context.Background()); err != nil || token != "fresh" {
		t.Fatalf("the next Token: %q, %v, want the refreshed token", token, err)
	}
}

func TestATokenRequestWhoseContextEndsInTheQueueNeverReachesTheGuest(t *testing.T) {
	guestOrSkip(t)
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	for name, lock := range map[string]interface {
		Acquire(context.Context) error
		Unlock()
	}{"the strategy's": &strategy.mu, "the profile's": &profile.root.mu} {
		t.Run(name, func(t *testing.T) {
			if err := lock.Acquire(context.Background()); err != nil {
				t.Fatal(err)
			}
			released := make(chan struct{})
			time.AfterFunc(200*time.Millisecond, func() { lock.Unlock(); close(released) })
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued Token: %v, want the deadline", err)
			}
			<-released
		})
	}
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
}

// The application's code that a guest call reaches (the RoundTripper, an
// OIDC provider) can hang, ignoring its context, or panic. Neither may close
// the profile or hold its lock past the caller.

// modalRoundTripper sends each request through next, or, while mode says
// so, panics, or hangs until release closes, or answers late. Each of those
// ignores the request's context, and keeps the request's body to check.
type modalRoundTripper struct {
	next     http.RoundTripper
	mode     atomic.Value // "", "panic", "hang" or "late"
	release  chan struct{}
	started  atomic.Int32 // hung requests
	finished atomic.Int32 // hung requests that have returned
	mu       sync.Mutex
	bodies   []*authRequestBody
}

func newModalRoundTripper(next http.RoundTripper) *modalRoundTripper {
	m := &modalRoundTripper{next: next, release: make(chan struct{})}
	m.mode.Store("")
	return m
}

func (m *modalRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	mode := m.mode.Load()
	if mode != "" {
		if body, ok := r.Body.(*authRequestBody); ok {
			m.mu.Lock()
			m.bodies = append(m.bodies, body)
			m.mu.Unlock()
		}
	}
	switch mode {
	case "panic":
		panic("roundtripper panic")
	case "hang":
		m.started.Add(1)
		<-m.release
		m.finished.Add(1)
		return nil, errors.New("too late")
	case "late":
		// Answers after the refresh grace, whatever the request's context.
		time.Sleep(300 * time.Millisecond)
		return m.next.RoundTrip(r.WithContext(context.Background()))
	}
	return m.next.RoundTrip(r)
}

// wantWiped fails unless every request body the RoundTripper kept was
// closed and wiped.
func (m *modalRoundTripper) wantWiped(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.bodies) == 0 {
		t.Fatal("the RoundTripper kept no request body")
	}
	for i, b := range m.bodies {
		b.mu.Lock()
		closed, wiped := b.closed, bytes.Equal(b.buf, make([]byte, len(b.buf)))
		b.mu.Unlock()
		if !closed || !wiped {
			t.Errorf("request body %d: closed %v, wiped %v; the access key is still in it", i, closed, wiped)
		}
	}
}

// eventually waits up to 5 seconds for cond.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("still waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// accessKeyWith builds an access-key strategy whose requests go through rt
// to a token service that answers every exchange.
func accessKeyWith(t *testing.T, rt *modalRoundTripper) (*ProfileStore, *Strategy) {
	t.Helper()
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, err := Open(context.Background(), t.TempDir(), WithRoundTripper(rt))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = profile.Close() })
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = strategy.Close() })
	return profile, strategy
}

func wantProfileOpen(t *testing.T, profile *ProfileStore) {
	t.Helper()
	if profile.root.closed || profile.root.inst.module.IsClosed() {
		t.Fatal("the profile was closed")
	}
}

// tokenRecovering calls Token and returns what it panicked with.
func tokenRecovering(ctx context.Context, s *Strategy) (p any, err error) {
	defer func() { p = recover() }()
	_, err = s.Token(ctx)
	return nil, err
}

// A RoundTripper that panics during a token request: the panic reaches the
// caller of Token, which can recover it, and the profile stays open. It
// used to be recovered by wazero as a guest trap, which closed the profile
// for good and never reached the caller (#1793).
func TestARoundTripperPanicDuringATokenRequestReachesTheCaller(t *testing.T) {
	guestOrSkip(t)
	rt := newModalRoundTripper(http.DefaultTransport)
	profile, strategy := accessKeyWith(t, rt)
	rt.mode.Store("panic")
	if p, err := tokenRecovering(context.Background(), strategy); p != "roundtripper panic" {
		t.Fatalf("Token: got panic %v (err %v), want the RoundTripper's panic", p, err)
	}
	wantProfileOpen(t, profile)
	rt.wantWiped(t)
	rt.mode.Store("")
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
}

// A RoundTripper that ignores its request's context: the caller's Token
// returns at its deadline, the next caller is not held behind the hung
// request, the request body is wiped, and the profile stays open. Once the
// RoundTripper returns, nothing is left running. The hung request used to
// hold the profile's lock until it returned, and the stuck-call backstop
// then closed the profile (#1795). The backstop is short here: wazero
// cannot stop a host function, but a guest call that came back from one
// after it fired would close the profile.
func TestATokenRequestWhoseRoundTripperIgnoresItsContextEndsAtTheDeadline(t *testing.T) {
	guestOrSkip(t)
	rt := newModalRoundTripper(http.DefaultTransport)
	profile, strategy := accessKeyWith(t, rt)
	profile.root.stuck = 20 * time.Millisecond
	before := runtime.NumGoroutine()
	rt.mode.Store("hang")
	released := false
	defer func() {
		if !released {
			close(rt.release)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Token: %v, want the deadline", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("Token returned after %v", waited)
	}
	// The hung request has not returned, and the next caller is served.
	rt.mode.Store("")
	next, cancelNext := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelNext()
	if token, err := strategy.Token(next); err != nil || token == "" {
		t.Fatalf("the next Token, with the first request still hung: %q, %v", token, err)
	}
	if n := rt.finished.Load(); n != 0 {
		t.Fatalf("%d hung request(s) returned early", n)
	}
	wantProfileOpen(t, profile)
	rt.wantWiped(t)
	close(rt.release)
	released = true
	eventually(t, "the hung request to return", func() bool { return rt.finished.Load() == 1 })
	// The next Token's request left a keep-alive connection, whose
	// goroutines are not the hung call's.
	eventually(t, "the goroutines left behind to end", func() bool {
		http.DefaultTransport.(*http.Transport).CloseIdleConnections()
		return runtime.NumGoroutine() <= before
	})
}

// Callers that give up leave hung code running, but only maxAbandoned
// calls of it: past that a call fails at once, as a transport failure,
// without calling the RoundTripper. Once they return, nothing is left
// running and calls go through again.
func TestHungRequestsLeftRunningAreCapped(t *testing.T) {
	guestOrSkip(t)
	rt := newModalRoundTripper(http.DefaultTransport)
	profile, strategy := accessKeyWith(t, rt)
	before := runtime.NumGoroutine()
	rt.mode.Store("hang")
	released := false
	defer func() {
		if !released {
			close(rt.release)
		}
	}()
	for range 3 * maxAbandoned {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _ = strategy.Token(ctx)
		cancel()
	}
	if n := rt.started.Load(); n != maxAbandoned {
		t.Fatalf("%d hung requests, want %d", n, maxAbandoned)
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, ErrTransport) {
		t.Fatalf("Token with %d requests hung: %v, want ErrTransport", maxAbandoned, err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("Token with the limit reached took %v, want at once", waited)
	}
	if n := rt.started.Load(); n != maxAbandoned {
		t.Fatalf("the RoundTripper was called %d times, want %d: the limit did not hold", n, maxAbandoned)
	}
	wantProfileOpen(t, profile)
	close(rt.release)
	released = true
	eventually(t, "the hung requests to return", func() bool { return rt.finished.Load() == maxAbandoned })
	eventually(t, "the goroutines left behind to end", func() bool { return runtime.NumGoroutine() <= before })
	rt.mode.Store("")
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
}

// A refresh whose RoundTripper ignores its context and answers after the
// refresh grace: the answer still reaches the guest, so the rotated
// refresh token is kept and the next Token is served from it.
func TestARefreshAnsweredAfterTheGraceByARoundTripperThatIgnoresItsContextIsKept(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			// The old refresh token is retired once the service answers.
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
	}))
	t.Cleanup(server.Close)
	rt := newModalRoundTripper(http.DefaultTransport)
	profile, err := Open(context.Background(), dir, WithRoundTripper(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	profile.root.inst.transport.grace = 100 * time.Millisecond
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	rt.mode.Store("late")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Token: %v, want the deadline", err)
	}
	eventually(t, "the late answer", func() bool { return requests.Load() == 1 })
	rt.mode.Store("")
	if token, err := strategy.Token(context.Background()); err != nil || token != "fresh" {
		t.Fatalf("the next Token: %q, %v, want the refreshed token", token, err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d refresh requests, want 1: the late answer was dropped", n)
	}
}

// The backstop: a refresh is waited for until the stuck-call backstop,
// past its grace, and one still hung then closes the profile. The caller
// has returned by then; the next call is ErrState.
func TestARefreshStillHungAtTheBackstopClosesTheProfile(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	rt := newModalRoundTripper(http.DefaultTransport)
	defer close(rt.release)
	profile, err := Open(context.Background(), dir, WithRoundTripper(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	profile.root.stuck = 50 * time.Millisecond
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL("https://cts.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	rt.mode.Store("hang")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stuck Token: %v, want the deadline", err)
	}
	eventually(t, "the backstop to close the profile", func() bool {
		profile.root.mu.Lock()
		defer profile.root.mu.Unlock()
		return profile.root.closed || profile.root.inst.module.IsClosed()
	})
	if _, err := strategy.Token(context.Background()); !errors.Is(err, ErrState) {
		t.Fatalf("a Token after the backstop: %v, want ErrState", err)
	}
}

// An OIDC provider is the application's code too: one that panics reaches
// the caller of Token, and one that ignores its context ends at the
// caller's deadline. Either way the profile stays open.
func TestAnOIDCProviderThatPanicsOrHangsLeavesTheProfileOpen(t *testing.T) {
	guestOrSkip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWT(t, "https://cts.example"), time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	var mode atomic.Value
	mode.Store("")
	release := make(chan struct{})
	defer close(release)
	strategy, err := profile.OIDC(context.Background(), testCRN, OIDCProviderFunc(func(context.Context) (string, error) {
		switch mode.Load() {
		case "panic":
			panic("provider panic")
		case "hang":
			<-release
			return "", errors.New("too late")
		}
		return "idp-token", nil
	}), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	mode.Store("panic")
	if p, err := tokenRecovering(context.Background(), strategy); p != "provider panic" {
		t.Fatalf("Token: got panic %v (err %v), want the provider's panic", p, err)
	}
	wantProfileOpen(t, profile)

	mode.Store("hang")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Token with a hung provider: %v, want the deadline", err)
	}
	wantProfileOpen(t, profile)

	mode.Store("")
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
}
