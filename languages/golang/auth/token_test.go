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
// except %p and %w, and through both slog handlers. The other fields stay
// visible, because they help a developer debug a login. fmt also redacts a
// Token in an exported field, a slice or a pointer, and so does the slog
// text handler. TestTokenPrintLimits covers the cases that are not redacted.
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
		logged := map[string]any{"value": tok, "pointer": &tok}
		if name == "text" {
			// The text handler prints a struct through fmt, so a Token in
			// an exported field is redacted. The JSON handler does not:
			// see TestTokenPrintLimits.
			logged["field"] = holder{Token: tok}
		}
		for valueName, v := range logged {
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

// TestTokenPrintLimits pins the cases that the Token doc comment says are
// not redacted. No method on Token can change them. If one of these checks
// fails, Go has changed, and the doc comment and CHANGELOG need updating.
func TestTokenPrintLimits(t *testing.T) {
	const secret = "tok-swordfish-0123456789"
	tok := auth.Token{AccessToken: secret, TokenType: "Bearer"}
	type holder struct{ Token auth.Token }
	type session struct {
		auth.Token
		User string
	}
	// go vet rejects %w with an argument that is not an error, so the
	// format is held in a variable to reach the run-time behaviour.
	wrap := "%w"

	var jsonLog bytes.Buffer
	slog.New(slog.NewJSONHandler(&jsonLog, nil)).Info("auth", "session", holder{Token: tok})

	// fmt prints a bad verb by reflection, without calling any method, and
	// the JSON handler encodes a nested struct with encoding/json.
	for name, out := range map[string]string{
		"%p":                   fmt.Sprintf("%p", tok),
		"%w with Sprintf":      fmt.Sprintf(wrap, tok),
		"%w with Errorf":       fmt.Errorf("auth: "+wrap, tok).Error(),
		"slog JSON, in struct": jsonLog.String(),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(out, secret) {
				t.Errorf("the access token is now redacted here: update the Token doc comment and the CHANGELOG")
			}
		})
	}

	// A struct that embeds Token takes its methods, so it prints as the
	// Token alone, and its own fields do not print.
	t.Run("embedded", func(t *testing.T) {
		out := fmt.Sprintf("%+v", session{Token: tok, User: "alice"})
		checkRedacted(t, out, secret, "an embedded Token")
		if strings.Contains(out, "alice") {
			t.Errorf("a struct that embeds Token now prints its own fields: update the Token doc comment and the CHANGELOG")
		}
	})
}

// checkRedacted fails when out contains the secret, its hex in either
// case, or its first 8 characters.
func checkRedacted(t *testing.T, out, secret, how string) {
	t.Helper()
	for _, form := range []string{secret, fmt.Sprintf("%x", secret), fmt.Sprintf("%X", secret), secret[:8]} {
		if strings.Contains(out, form) {
			t.Fatalf("%s printed the access token: the output holds a form of it (%d bytes of output)", how, len(out))
		}
	}
}
