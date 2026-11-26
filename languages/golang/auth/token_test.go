package auth_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// A Token printed or logged hides its access token, under every fmt verb
// and through both slog handlers. The other fields stay visible, because
// they help a developer debug a login. A Token inside another value is
// redacted too, as long as fmt or slog can reach its methods.
func TestTokenPrintsAndLogsRedacted(t *testing.T) {
	const secret = "tok-swordfish-0123456789"
	tok := auth.Token{
		AccessToken:      secret,
		TokenType:        "Bearer",
		ExpiresAt:        time.Date(2026, 11, 26, 1, 2, 3, 0, time.UTC),
		Region:           "ap-southeast-2",
		ClientID:         "6a70bd18-99ac-4650-b104-37eec3a15b09",
		DeviceInstanceID: "0f4a4fd7-4a1a-4c5e-9d3e-7a4c8e3a9c11",
	}
	// Each of these must appear in every printed form.
	visible := []string{"[redacted]", "Bearer", "2026-11-26", "ap-southeast-2", tok.ClientID, tok.DeviceInstanceID}

	type holder struct{ Token auth.Token }
	values := map[string]any{
		"value":   tok,
		"pointer": &tok,
		"field":   holder{Token: tok},
		"slice":   []auth.Token{tok},
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10.3v"}
	for name, v := range values {
		for _, verb := range verbs {
			t.Run(name+" "+verb, func(t *testing.T) {
				out := fmt.Sprintf(verb, v)
				checkRedacted(t, out, secret, verb)
				// %x, %X and %q change the text of a value that fmt prints
				// as itself, so only the plain verbs keep the fields readable.
				if verb == "%x" || verb == "%X" || verb == "%q" || verb == "%10.3v" || verb == "%d" {
					return
				}
				for _, want := range visible {
					if !strings.Contains(out, want) {
						t.Errorf("printed %s, which does not contain %q", out, want)
					}
				}
			})
		}
	}

	for name, call := range map[string]func() string{
		"Sprint":   func() string { return fmt.Sprint(tok) },
		"Sprintln": func() string { return fmt.Sprintln(tok) },
		"String":   tok.String,
		"GoString": tok.GoString,
	} {
		t.Run(name, func(t *testing.T) {
			out := call()
			checkRedacted(t, out, secret, name)
			for _, want := range visible {
				if !strings.Contains(out, want) {
					t.Errorf("printed %s, which does not contain %q", out, want)
				}
			}
		})
	}

	handlers := map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	}
	for name, newHandler := range handlers {
		for valueName, v := range map[string]any{"value": tok, "pointer": &tok} {
			t.Run("slog "+name+" "+valueName, func(t *testing.T) {
				var b bytes.Buffer
				slog.New(newHandler(&b)).Info("auth", "token", v)
				out := b.String()
				checkRedacted(t, out, secret, "slog")
				for _, want := range visible {
					if !strings.Contains(out, want) {
						t.Errorf("logged %s, which does not contain %q", out, want)
					}
				}
			})
		}
	}
}

// A Token with no access token prints the same shape. It does not say
// whether the token was empty, so the output never depends on it.
func TestTokenZeroValuePrints(t *testing.T) {
	got := fmt.Sprint(auth.Token{})
	if !strings.HasPrefix(got, "auth.Token{AccessToken: [redacted]") {
		t.Errorf("printed %s", got)
	}
}

// checkRedacted fails when out holds the secret, or any form of it that fmt
// could write: hex in either case, or quoted.
func checkRedacted(t *testing.T, out, secret, how string) {
	t.Helper()
	for _, form := range []string{secret, fmt.Sprintf("%x", secret), fmt.Sprintf("%X", secret), secret[:8]} {
		if strings.Contains(out, form) {
			t.Fatalf("%s printed the access token: the output holds a form of it (%d bytes of output)", how, len(out))
		}
	}
}
