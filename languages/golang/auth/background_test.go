package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
