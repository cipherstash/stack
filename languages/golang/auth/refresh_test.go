package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A strategy is shared by every caller in a process: one exchange with the
// token service, which can take a second or more, must not hold up the
// others while they have a token that still works (#1958).

// subject is a test token's sub claim, its name here, or "" for anything
// else. Safe off the test's goroutine, unlike jwtSubject.
func subject(token string) string {
	var claims struct {
		Sub string `json:"sub"`
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Sub
}

// While a token that is still valid is refreshed in the background, every
// caller gets that token at once, rather than waiting for the token
// service to answer.
func TestCallersDoNotWaitBehindARefreshOfAValidToken(t *testing.T) {
	guestOrSkip(t)
	const delay = time.Second
	server, requests, refreshing := shortTokenServer(t, 4*time.Second, delay)
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

	// The first Token exchanges; the second uses the token, so its
	// refresh ahead of expiry is due half way through its life.
	for range 2 {
		if token, err := strategy.Token(context.Background()); err != nil || jwtSubject(t, token) != "1" {
			t.Fatalf("Token: %q, %v", token, err)
		}
	}
	select {
	case <-refreshing:
	case <-time.After(5 * time.Second):
		t.Fatal("no refresh started")
	}

	const callers = 8
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			start := time.Now()
			token, err := strategy.Token(context.Background())
			if waited := time.Since(start); waited > delay/4 {
				t.Errorf("caller %d waited %v behind the refresh", i, waited)
			}
			if err != nil || subject(token) != "1" {
				t.Errorf("caller %d got token %q, %v, want the current token, %q", i, subject(token), err, "1")
			}
		})
	}
	wg.Wait()
	if n := requests.Load(); n != 2 {
		t.Fatalf("%d exchanges, want 2: the first, and one refresh", n)
	}
	eventually(t, "the refreshed token", func() bool {
		token, err := strategy.Token(context.Background())
		return err == nil && subject(token) == "2"
	})
}

// heldServer answers access-key exchanges with an hour-long token named by
// the exchange's number ("1", "2", ...), each after release is closed, or
// after its client gives up (which it does not answer). It counts the
// exchanges and announces each on started.
func heldServer(t *testing.T) (server *httptest.Server, requests *atomic.Int32, started chan struct{}, release chan struct{}) {
	t.Helper()
	requests = new(atomic.Int32)
	started = make(chan struct{}, 256)
	release = make(chan struct{})
	var issuer string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		n := requests.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWTFor(t, issuer, fmt.Sprint(n)), time.Now().Add(time.Hour).Unix())
	}))
	issuer = server.URL
	t.Cleanup(server.Close)
	return server, requests, started, release
}

func heldAccessKey(t *testing.T, server *httptest.Server) (*ProfileStore, *Strategy) {
	t.Helper()
	profile, err := Open(context.Background(), t.TempDir())
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

// awaitParked waits until n token operations are parked in the guest.
func awaitParked(t *testing.T, profile *ProfileStore, n int) {
	t.Helper()
	eventually(t, fmt.Sprintf("%d parked callers", n), func() bool {
		profile.root.mu.Lock()
		defer profile.root.mu.Unlock()
		return len(profile.root.parked) == n
	})
}

// Callers that arrive while the first token is exchanged wait for that
// exchange rather than each starting one: many callers at once, more than
// the guest holds paused, make one request, and all get its token.
func TestManyCallersWithNoTokenYetShareOneExchange(t *testing.T) {
	guestOrSkip(t)
	server, requests, started, release := heldServer(t)
	profile, strategy := heldAccessKey(t, server)

	const callers = 2 * maxPaused
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			token, err := strategy.Token(context.Background())
			if err != nil || subject(token) != "1" {
				t.Errorf("caller %d got token %q, %v, want the one exchange's", i, subject(token), err)
			}
		})
	}
	<-started
	// Every slot but the exchange's is a parked caller; the rest wait for
	// a slot.
	awaitParked(t, profile, maxPaused-1)
	close(release)
	wg.Wait()
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d exchanges, want 1", n)
	}
	wantProfileOpen(t, profile)
	// The strategy's refresh loop may hold an operation open for a moment,
	// asking when the next refresh is due.
	eventually(t, "no operation open", func() bool {
		profile.root.mu.Lock()
		defer profile.root.mu.Unlock()
		return profile.root.open == 0
	})
}

// A caller waiting for another's exchange that gives up returns at its
// deadline; the exchange and the callers still waiting are unaffected.
func TestAWaitingCallerThatGivesUpLeavesTheExchangeAlone(t *testing.T) {
	guestOrSkip(t)
	server, requests, started, release := heldServer(t)
	profile, strategy := heldAccessKey(t, server)

	first := make(chan string, 1)
	go func() {
		token, err := strategy.Token(context.Background())
		if err != nil {
			t.Errorf("the exchanging caller: %v", err)
		}
		first <- subject(token)
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the waiting caller: %v, want its deadline", err)
	}
	awaitParked(t, profile, 0)
	close(release)
	if got := <-first; got != "1" {
		t.Fatalf("the exchanging caller got %q", got)
	}
	if token, err := strategy.Token(context.Background()); err != nil || subject(token) != "1" {
		t.Fatalf("a later Token: %q, %v", subject(token), err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d exchanges, want 1", n)
	}
	wantProfileOpen(t, profile)
}

// The caller whose exchange is in flight gives up. An access-key exchange
// rotates nothing, so its request is cancelled with it, and its operation
// is finished with that failure rather than dropped; a caller waiting for
// it then exchanges in its place.
func TestAWaitingCallerTakesOverAnExchangeWhoseCallerGaveUp(t *testing.T) {
	guestOrSkip(t)
	server, requests, started, release := heldServer(t)
	profile, strategy := heldAccessKey(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	gaveUp := make(chan error, 1)
	go func() {
		_, err := strategy.Token(ctx)
		gaveUp <- err
	}()
	<-started
	waiting := make(chan string, 1)
	go func() {
		token, err := strategy.Token(context.Background())
		if err != nil {
			t.Errorf("the waiting caller: %v", err)
		}
		waiting <- subject(token)
	}()
	awaitParked(t, profile, 1)
	cancel()
	if err := <-gaveUp; !errors.Is(err, context.Canceled) {
		t.Fatalf("the caller that gave up: %v, want context.Canceled", err)
	}
	<-started
	close(release)
	if got := <-waiting; got != "2" {
		t.Fatalf("the waiting caller got token %q, want the second exchange's", got)
	}
	if n := requests.Load(); n != 2 {
		t.Fatalf("%d exchanges, want 2", n)
	}
	wantProfileOpen(t, profile)
}
