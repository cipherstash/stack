package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// A strategy's token is refreshed in the background, ahead of its expiry,
// so no caller with a token that still works waits for the token service.

// shortTokenServer answers access-key exchanges with tokens that last
// lifetime, named by the exchange's number ("1", "2", ...). Every exchange
// after the first is announced on refreshing and answered after delay.
func shortTokenServer(t *testing.T, lifetime, delay time.Duration) (server *httptest.Server, requests *atomic.Int32, refreshing chan struct{}) {
	t.Helper()
	requests = new(atomic.Int32)
	refreshing = make(chan struct{}, 64)
	var issuer string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		n := requests.Add(1)
		if n > 1 {
			select {
			case refreshing <- struct{}{}:
			default:
			}
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWTFor(t, issuer, fmt.Sprint(n)), time.Now().Add(lifetime).Unix())
	}))
	issuer = server.URL
	t.Cleanup(server.Close)
	return server, requests, refreshing
}

// A token inside the 90-second refresh window still works: the caller
// gets it at once, and neither starts nor waits for its refresh.
func TestACallerWithAValidTokenDoesNotWaitForItsRefresh(t *testing.T) {
	guestOrSkip(t)
	const delay = time.Second
	server, _, _ := shortTokenServer(t, 60*time.Second, delay)
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

	if token, err := strategy.Token(context.Background()); err != nil || jwtSubject(t, token) != "1" {
		t.Fatalf("the first Token: %q, %v", token, err)
	}
	start := time.Now()
	token, err := strategy.Token(context.Background())
	if waited := time.Since(start); waited > delay/4 {
		t.Errorf("the caller waited %v for a refresh its valid token did not need", waited)
	}
	if err != nil || jwtSubject(t, token) != "1" {
		t.Errorf("got %q, %v, want the current token, %q", jwtSubject(t, token), err, "1")
	}
}

// A token in use is refreshed before it expires, with no caller asking.
func TestATokenInUseIsRefreshedBeforeItExpires(t *testing.T) {
	guestOrSkip(t)
	const lifetime = 4 * time.Second
	server, requests, refreshing := shortTokenServer(t, lifetime, 0)
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

	// The first Token exchanges. The second uses the token, so it is due a
	// refresh ahead of its expiry, which no caller makes: the token still
	// works.
	if _, err := strategy.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if token, err := strategy.Token(context.Background()); err != nil || jwtSubject(t, token) != "1" {
		t.Fatalf("the second Token: %q, %v: a caller refreshed a token that still worked", jwtSubject(t, token), err)
	}
	select {
	case <-refreshing:
	case <-time.After(lifetime):
		t.Fatalf("no refresh before the token expired: %d exchanges", requests.Load())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		token, err := strategy.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if jwtSubject(t, token) == "2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the refreshed token was never handed out: still %q", jwtSubject(t, token))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// loopEnded reports whether a refresh loop has returned.
func loopEnded(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// Close ends the strategy's refresh loop before it returns.
func TestClosingAStrategyEndsItsRefreshLoop(t *testing.T) {
	guestOrSkip(t)
	server, _, _ := shortTokenServer(t, time.Hour, 0)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	// Used twice, so the loop sleeps until the refresh ahead is due.
	for range 2 {
		if _, err := strategy.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	done := strategy.loopDone
	if err := strategy.Close(); err != nil {
		t.Fatal(err)
	}
	if !loopEnded(done) {
		t.Fatal("Close returned with the refresh loop still running")
	}
}

// Closing the profile ends the refresh loops of its strategies, which
// their own Close then finds ended.
func TestClosingTheProfileEndsItsStrategiesRefreshLoops(t *testing.T) {
	_, store := profile(t)
	server, _, _ := shortTokenServer(t, time.Hour, 0)
	key, err := store.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	ws, err := store.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	device, err := ws.DeviceSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Strategy{key, device} {
		eventually(t, "the refresh loop ended", func() bool { return loopEnded(s.loopDone) })
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// A strategy its application never closes is still collected: its refresh
// loop holds it only weakly, and ends when it goes.
func TestAForgottenStrategysRefreshLoopEnds(t *testing.T) {
	guestOrSkip(t)
	server, _, _ := shortTokenServer(t, time.Hour, 0)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	done := func() <-chan struct{} {
		strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := strategy.Token(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		return strategy.loopDone
	}()
	eventually(t, "the forgotten strategy's loop ended", func() bool {
		runtime.GC()
		return loopEnded(done)
	})
}

// Every refresh loop a test started has ended once its strategies and
// profiles are closed.
func TestNoRefreshLoopOutlivesItsStrategies(t *testing.T) {
	guestOrSkip(t)
	server, _, _ := shortTokenServer(t, time.Hour, 0)
	before := refreshLoops.Load()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var strategies []*Strategy
	for range 4 {
		s, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
		strategies = append(strategies, s)
	}
	if n := refreshLoops.Load() - before; n < 4 {
		t.Fatalf("%d refresh loops started for 4 strategies", n)
	}
	for _, s := range strategies {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := profile.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "every refresh loop this test started ended", func() bool { return refreshLoops.Load() <= before })
}
