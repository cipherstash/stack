package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testAccessKey is the access key the tests in this file present. No error
// may show it, or any part of it.
const testAccessKey = "CSAKtestKeyId.testKeySecret"

// accessKeyToken runs one access-key exchange against baseURL and returns
// the error.
func accessKeyToken(t *testing.T, baseURL string) error {
	t.Helper()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = profile.Close() })
	strategy, err := profile.AccessKey(context.Background(), testCRN, testAccessKey, WithBaseURL(baseURL))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = strategy.Close() })
	_, err = strategy.Token(context.Background())
	if err == nil {
		t.Fatal("Token succeeded, want an error")
	}
	return err
}

// wantNoKey fails the test if err, or its Diagnostic, shows the access key
// or a part of it.
func wantNoKey(t *testing.T, err error) {
	t.Helper()
	shown := err.Error()
	var d *Diagnostic
	if errors.As(err, &d) {
		shown += fmt.Sprintf(" %+v", *d)
	}
	for _, part := range []string{"CSAK", "testKeyId", "testKeySecret"} {
		if strings.Contains(shown, part) {
			t.Fatalf("the error shows the access key (%q): %s", part, shown)
		}
	}
}

// The auth service answers a rejected access key with HTTP 401. That is a
// credential error, not a transport failure: sending the same key again
// fails the same way, so a program that retries ErrTransport must not see
// it. The Help says to check the access key, and nothing shows the key.
func TestRejectedAccessKeyIsACredentialError(t *testing.T) {
	guestOrSkip(t)
	bodies := map[string]string{
		"with a description":     `{"error":"unauthorized","error_description":"Access key was malformed"}`,
		"with no body":           "",
		"a page echoing the key": "<html><h1>401</h1>" + testAccessKey + "</html>",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			err := accessKeyToken(t, server.URL)
			if !errors.Is(err, ErrInvalidClient) {
				t.Fatalf("Token error = %v, want ErrInvalidClient", err)
			}
			if errors.Is(err, ErrTransport) {
				t.Fatalf("Token error = %v matches ErrTransport; a rejected key is not worth retrying", err)
			}
			if !strings.Contains(err.Error(), "HTTP 401") {
				t.Errorf("Token error = %q, want it to name HTTP 401", err)
			}
			d := wantDiagnostic(t, err, "stack_auth::invalid_client")
			if !strings.Contains(d.Help, "access key") {
				t.Errorf("Help = %q, want it to say to check the access key", d.Help)
			}
			wantNoKey(t, err)
		})
	}
}

// A 403 from the auth service stays a transport failure. The edge in front
// of the auth service answers 403 before the auth service reads the key
// (see TestAuthRequestsIdentifyTheLibraryNotGo), so a 403 does not say the
// key is wrong, and a Help that said so would mislead.
func TestForbiddenAccessKeyExchangeStaysATransportFailure(t *testing.T) {
	guestOrSkip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<html><h1>403 Forbidden</h1></html>", http.StatusForbidden)
	}))
	defer server.Close()
	err := accessKeyToken(t, server.URL)
	if !errors.Is(err, ErrTransport) || errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Token error = %v, want ErrTransport and not ErrInvalidClient", err)
	}
	wantNoKey(t, err)
}

// A network failure keeps the net error, so errors.As reaches the
// *net.OpError and the message says what failed. It is still ErrTransport.
func TestAuthNetworkFailureWrapsTheNetError(t *testing.T) {
	guestOrSkip(t)
	// A closed port: the dial is refused.
	server := httptest.NewServer(http.NotFoundHandler())
	addr := server.URL
	server.Close()
	err := accessKeyToken(t, addr)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("Token error = %v, want ErrTransport", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("Token error = %v, want it to wrap a *net.OpError", err)
	}
	if opErr.Op != "dial" {
		t.Errorf("net.OpError.Op = %q, want dial", opErr.Op)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Errorf("Token error = %v, want it to match net.Error", err)
	}
	if !strings.Contains(err.Error(), opErr.Error()) {
		t.Errorf("Token error = %q, want it to include %q", err, opErr.Error())
	}
	wantCode(t, err, "stack_auth::request_error")
	wantNoKey(t, err)
}

// Only a net error is kept, never the RoundTripper's whole error: a
// *url.Error's text names the request's URL, and a RoundTripper's own
// error text can carry anything.
func TestAuthNetworkFailureKeepsOnlyTheNetError(t *testing.T) {
	guestOrSkip(t)
	const marker = "leak-marker-url"
	opErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("Post %q: %w", r.URL.String()+"?"+marker, opErr)
	})
	profile, err := Open(context.Background(), t.TempDir(), WithRoundTripper(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, testAccessKey, WithBaseURL("https://cts.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, opErr) {
		t.Fatalf("Token error = %v, want it to wrap the RoundTripper's *net.OpError", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("Token error = %q shows the RoundTripper's text", err)
	}
}
