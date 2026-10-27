package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceTokenSnapshot(t *testing.T) {
	guestOrSkip(t)
	for _, kind := range []string{"access_key", "oidc"} {
		t.Run(kind, func(t *testing.T) {
			var jwt string
			var exchanges atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/authorise" {
					t.Errorf("unexpected auth request: %s %s", r.Method, r.URL.Path)
				}
				exchanges.Add(1)
				fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
			}))
			defer server.Close()
			// The strategy uses CTS's exchange expiry, not JWT verification. These
			// claims and the unsigned fixture must not trigger a local policy check.
			claims := testClaims(server.URL, "CS|test", "ZVATKW3VHMFG27DY")
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
			claims["aud"] = "another-service"
			jwt = unsignedJWT(t, claims)
			ctx := context.Background()
			profile, err := OpenWithoutProfile(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer profile.Close()
			var strategy *Strategy
			if kind == "access_key" {
				strategy, err = profile.AccessKey(ctx, testCRN, NewAccessKey([]byte("CSAKtestKeyId.testKeySecret")), WithBaseURL(server.URL))
			} else {
				strategy, err = profile.OIDC(ctx, testCRN, OIDCProviderFunc(func(context.Context) (string, error) { return "idp-token", nil }), WithBaseURL(server.URL))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer strategy.Close()
			for i := 0; i < 2; i++ {
				bearer, err := strategy.Token(ctx)
				if err != nil || bearer != jwt {
					t.Fatalf("bearer differs from acquired token: %v", err)
				}
				token, err := strategy.ServiceToken(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if token.Bearer() != jwt || token.WorkspaceCRN() != testCRN || token.WorkspaceID() != "ZVATKW3VHMFG27DY" || token.Issuer() != server.URL+"/" || token.ZeroKMSURL() != "https://ap-southeast-2.aws.viturhosted.net/" {
					t.Fatal("snapshot differs from the acquired token's claims")
				}
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
					if strings.Contains(fmt.Sprintf(verb, token), jwt) {
						t.Fatal("formatted token leaked")
					}
				}
				encoded, err := json.Marshal(map[string]any{"token": token})
				if err != nil {
					t.Fatal(err)
				}
				if string(encoded) != `{"token":{}}` {
					t.Fatal("serialized token leaked")
				}
			}
			if exchanges.Load() != 1 {
				t.Fatalf("auth requests = %d, want one cached acquisition", exchanges.Load())
			}
		})
	}
}

func TestAccessKeyOwnedWipedOnSuccessAndFailure(t *testing.T) {
	guestOrSkip(t)
	ctx := context.Background()
	profile, err := OpenWithoutProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	for _, crn := range []string{"invalid", testCRN} {
		t.Run(crn, func(t *testing.T) {
			material := []byte("CSAKtestKeyId.testKeySecret")
			key := NewAccessKey(material)
			for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%s", "%d"} {
				if fmt.Sprintf(verb, key) != "AccessKey(***)" || fmt.Sprintf(verb, *key) != "AccessKey(***)" {
					t.Fatal("key did not redact")
				}
			}
			strategy, err := profile.AccessKey(ctx, crn, key)
			if strategy != nil {
				defer strategy.Close()
			}
			if crn == "invalid" {
				if !errors.Is(err, ErrConfig) || strategy != nil {
					t.Fatalf("invalid CRN: strategy %v, error %v", strategy, err)
				}
			} else if err != nil || strategy == nil {
				t.Fatalf("valid CRN: strategy %v, error %v", strategy, err)
			}
			if !key.IsZero() || strings.Trim(string(material), "\x00") != "" {
				t.Fatal("AccessKey did not consume owned bytes")
			}
			key.Wipe()
		})
	}
}

func TestServiceTokenZeroAndEmptyEnvelope(t *testing.T) {
	var zero ServiceToken
	if zero.Bearer() != "" || zero.WorkspaceID() != "" || zero.WorkspaceCRN() != "" || zero.Issuer() != "" || zero.ZeroKMSURL() != "" {
		t.Fatal("zero token contains credentials or metadata")
	}
	if _, err := decodeServiceToken([]byte(`{}`)); !errors.Is(err, ErrInternal) {
		t.Fatal("empty guest envelope accepted")
	}
}

func TestTokenDoesNotRequireZeroKMSMetadata(t *testing.T) {
	guestOrSkip(t)
	var jwt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	claims := testClaims(server.URL, "CS|test", "ZVATKW3VHMFG27DY")
	claims["services"] = map[string]string{}
	jwt = unsignedJWT(t, claims)
	ctx := context.Background()
	store, err := OpenWithoutProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	strategy, err := store.AccessKey(ctx, testCRN, NewAccessKey([]byte("CSAKtestKeyId.testKeySecret")), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	if bearer, err := strategy.Token(ctx); err != nil || bearer != jwt {
		t.Fatalf("bearer acquisition required snapshot metadata: %v", err)
	}
	if _, err := strategy.ServiceToken(ctx); !errors.Is(err, ErrConfig) {
		t.Fatalf("snapshot without ZeroKMS metadata: %v, want ErrConfig", err)
	}
	if bearer, err := strategy.Token(ctx); err != nil || bearer != jwt {
		t.Fatalf("snapshot failure affected cached bearer: %v", err)
	}
}

func TestDeviceTokenDoesNotRequireZeroKMSMetadata(t *testing.T) {
	guestOrSkip(t)
	for _, first := range []string{"bearer", "snapshot"} {
		t.Run(first, func(t *testing.T) {
			dir, workspaceDir := expiredDeviceProfile(t)
			var jwt string
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`, jwt)
			}))
			defer server.Close()
			claims := testClaims(server.URL, "device", wsA)
			claims["services"] = map[string]string{}
			jwt = unsignedJWT(t, claims)
			ctx := context.Background()
			store, err := Open(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			workspace, err := store.WorkspaceStore(ctx, wsA)
			if err != nil {
				t.Fatal(err)
			}
			strategy, err := workspace.DeviceSession(ctx, WithBaseURL(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			defer strategy.Close()
			// Exercise both refresh exports. A metadata failure must not discard
			// the rotated credential or prevent a subsequent bearer-only read.
			if first == "snapshot" {
				if _, err := strategy.ServiceToken(ctx); !errors.Is(err, ErrConfig) {
					t.Fatalf("refreshed snapshot without metadata: %v", err)
				}
			}
			for i := 0; i < 2; i++ {
				if bearer, err := strategy.Token(ctx); err != nil || bearer != jwt {
					t.Fatalf("refreshed/cached bearer required metadata: %v", err)
				}
				if _, err := strategy.ServiceToken(ctx); !errors.Is(err, ErrConfig) {
					t.Fatalf("cached snapshot without metadata: %v", err)
				}
			}
			if requests.Load() != 1 {
				t.Fatalf("refresh requests = %d, want 1", requests.Load())
			}
			data, err := os.ReadFile(filepath.Join(workspaceDir, "auth.json"))
			if err != nil {
				t.Fatal(err)
			}
			var stored struct {
				RefreshToken string `json:"refresh_token"`
			}
			if err := json.Unmarshal(data, &stored); err != nil || stored.RefreshToken != "refresh-2" {
				t.Fatalf("rotated refresh token was not saved: %v", err)
			}
		})
	}
}
