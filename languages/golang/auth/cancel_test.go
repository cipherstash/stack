package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
// so, panics or hangs until release closes, ignoring the request's context.
type modalRoundTripper struct {
	next     http.RoundTripper
	mode     atomic.Value // "", "panic" or "hang"
	release  chan struct{}
	finished atomic.Int32 // hung requests that have returned
}

func newModalRoundTripper(next http.RoundTripper) *modalRoundTripper {
	m := &modalRoundTripper{next: next, release: make(chan struct{})}
	m.mode.Store("")
	return m
}

func (m *modalRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	switch m.mode.Load() {
	case "panic":
		panic("roundtripper panic")
	case "hang":
		<-m.release
		m.finished.Add(1)
		return nil, errors.New("too late")
	}
	return m.next.RoundTrip(r)
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
	rt.mode.Store("")
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
}

// A RoundTripper that ignores its request's context: the caller's Token
// returns at its deadline, the next caller is not held behind the hung
// request, and the profile stays open. The hung request used to hold the
// profile's lock until it returned, and the stuck-call backstop then closed
// the profile (#1795). The backstop is short here, so a guest call still
// waiting on the request would trip it.
func TestATokenRequestWhoseRoundTripperIgnoresItsContextEndsAtTheDeadline(t *testing.T) {
	guestOrSkip(t)
	rt := newModalRoundTripper(http.DefaultTransport)
	profile, strategy := accessKeyWith(t, rt)
	profile.root.stuck = 20 * time.Millisecond
	rt.mode.Store("hang")
	defer close(rt.release)
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
