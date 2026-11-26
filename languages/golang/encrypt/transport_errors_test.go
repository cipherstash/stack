package encrypt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// closedURL is the URL of a port that nothing listens on any more.
func closedURL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()
	return url
}

// A rejected access key reaches the caller of NewClient as auth's
// credential error, with the Help that says to check the key. The error
// still matches ErrTransport, as every token source failure does: the guest
// reports a failed token fetch as a transport failure, and callers check
// the auth name to tell the two apart.
func TestNewClientWithARejectedAccessKey(t *testing.T) {
	guestOrSkip(t)
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	cts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized","error_description":"Access key was malformed"}`)
	}))
	t.Cleanup(cts.Close)
	t.Setenv("CS_CTS_HOST", cts.URL)
	zerokms := newStub(t, http.StatusOK, "application/json", "{}")
	t.Setenv("CS_ZEROKMS_HOST", zerokms.URL)
	_, err := NewClient(context.Background(), WithCredentials(testAccessKeyCredentials()))
	if !errors.Is(err, auth.ErrInvalidClient) || !errors.Is(err, ErrTransport) {
		t.Fatalf("NewClient: %v, want auth.ErrInvalidClient and ErrTransport", err)
	}
	if errors.Is(err, auth.ErrTransport) {
		t.Fatalf("NewClient: %v matches auth.ErrTransport, want a credential error", err)
	}
	d := wantDiagnostic(t, err, "stack_auth::invalid_client")
	if !strings.Contains(d.Help, "access key") {
		t.Errorf("Help = %q, want it to say to check the access key", d.Help)
	}
	if shown := fmt.Sprintf("%v %+v", err, *d); strings.Contains(shown, testAccessKey) {
		t.Fatalf("the error shows the access key: %s", shown)
	}
	if len(zerokms.requests) != 0 {
		t.Fatalf("ZeroKMS was asked without a token: %+v", zerokms.requests)
	}
}

// When ZeroKMS cannot be reached, the error wraps the net error, so
// errors.As reaches the *net.OpError. It is still ErrTransport.
func TestZeroKMSNetworkFailureWrapsTheNetError(t *testing.T) {
	guestOrSkip(t)
	_, err := NewClient(context.Background(), testConfig(closedURL(t))...)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("NewClient: %v, want ErrTransport", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("NewClient: %v, want it to wrap a *net.OpError", err)
	}
	if opErr.Op != "dial" {
		t.Errorf("net.OpError.Op = %q, want dial", opErr.Op)
	}
	if !strings.Contains(err.Error(), opErr.Error()) {
		t.Errorf("NewClient: %q, want it to include %q", err, opErr.Error())
	}
	// The guest's detail is still the Diagnostic errors.As finds.
	_ = wantDiagnostic(t, err, "stack_kms::load_keyset_failed")
}

// Only the net error is kept, never the RoundTripper's whole error: a
// *url.Error's text names the request's URL.
func TestZeroKMSNetworkFailureKeepsOnlyTheNetError(t *testing.T) {
	guestOrSkip(t)
	const marker = "leak-marker-url"
	opErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	cfg := testConfig("http://zerokms.invalid")
	cfg = append(cfg, WithTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("Post %q: %w", r.URL.String()+"?"+marker, opErr)
	})))
	_, err := NewClient(context.Background(), cfg...)
	if !errors.Is(err, ErrTransport) || !errors.Is(err, opErr) {
		t.Fatalf("NewClient: %v, want ErrTransport wrapping the RoundTripper's *net.OpError", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("NewClient: %q shows the RoundTripper's text", err)
	}
}

// When the auth service cannot be reached, the error NewClient returns
// wraps the net error too: the token source's error is kept.
func TestAuthNetworkFailureReachesNewClient(t *testing.T) {
	guestOrSkip(t)
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	t.Setenv("CS_CTS_HOST", closedURL(t))
	zerokms := newStub(t, http.StatusOK, "application/json", "{}")
	t.Setenv("CS_ZEROKMS_HOST", zerokms.URL)
	_, err := NewClient(context.Background(), WithCredentials(testAccessKeyCredentials()))
	if !errors.Is(err, auth.ErrTransport) {
		t.Fatalf("NewClient: %v, want auth.ErrTransport", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("NewClient: %v, want it to wrap a *net.OpError", err)
	}
}
