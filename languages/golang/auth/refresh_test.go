package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// slowRefreshServer answers the first access-key exchange at once with a
// token inside the guest's 90-second refresh window (so the next Token
// refreshes it), named "old". Every later exchange is announced on
// refreshing and answered after delay, with a token named "new" that lasts
// an hour.
func slowRefreshServer(t *testing.T, delay time.Duration) (server *httptest.Server, requests *atomic.Int32, refreshing chan struct{}) {
	t.Helper()
	requests = new(atomic.Int32)
	refreshing = make(chan struct{}, 16)
	var issuer string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if requests.Add(1) == 1 {
			fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWTFor(t, issuer, "old"), time.Now().Add(60*time.Second).Unix())
			return
		}
		refreshing <- struct{}{}
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWTFor(t, issuer, "new"), time.Now().Add(time.Hour).Unix())
	}))
	issuer = server.URL
	t.Cleanup(server.Close)
	return server, requests, refreshing
}

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

// While one caller refreshes a token that is still valid, every other
// caller gets that token at once, rather than waiting for the token
// service to answer.
func TestCallersDoNotWaitBehindARefreshOfAValidToken(t *testing.T) {
	guestOrSkip(t)
	const delay = time.Second
	server, requests, refreshing := slowRefreshServer(t, delay)
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

	if token, err := strategy.Token(context.Background()); err != nil || jwtSubject(t, token) != "old" {
		t.Fatalf("the first Token: %q, %v", token, err)
	}
	refreshed := make(chan string, 1)
	go func() {
		token, err := strategy.Token(context.Background())
		if err != nil {
			t.Errorf("the refreshing Token: %v", err)
		}
		refreshed <- token
	}()
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
			if err != nil || subject(token) != "old" {
				t.Errorf("caller %d got token %q, %v, want the current token, %q", i, subject(token), err, "old")
			}
		})
	}
	wg.Wait()

	if token := <-refreshed; jwtSubject(t, token) != "new" {
		t.Fatalf("the refreshing Token got %q, want the new token", jwtSubject(t, token))
	}
	if token, err := strategy.Token(context.Background()); err != nil || jwtSubject(t, token) != "new" {
		t.Fatalf("a Token after the refresh: %q, %v", token, err)
	}
	if n := requests.Load(); n != 2 {
		t.Fatalf("%d exchanges, want 2: the first, and one refresh", n)
	}
}
