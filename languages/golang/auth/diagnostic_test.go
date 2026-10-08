package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// wantDiagnostic asserts that err carries a *Diagnostic with code and a
// message, and returns it.
func wantDiagnostic(t *testing.T, err error, code string) *Diagnostic {
	t.Helper()
	var d *Diagnostic
	if !errors.As(err, &d) {
		t.Fatalf("%v carries no Diagnostic", err)
	}
	if d.Code != code {
		t.Fatalf("code = %q, want %q (%v)", d.Code, code, err)
	}
	if d.Message == "" {
		t.Fatalf("%s has no message", code)
	}
	return d
}

// wantCode is wantDiagnostic for a test that needs only the code.
func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	_ = wantDiagnostic(t, err, code)
}

// Each kind the profile store reports is its sentinel for errors.Is and a
// Diagnostic for errors.As. The strategies' kinds are asserted beside the
// tests that provoke them, in strategy_test.go. ErrInvalidFilename is not
// here: the store refuses every filename the guest would before asking it.
func TestEachStoreKindCarriesItsDiagnostic(t *testing.T) {
	ctx := context.Background()
	dir, s := profile(t)
	ws, err := s.WorkspaceStore(ctx, wsB)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		run  func() error
		want error
		code string
	}{
		{"no current workspace", func() error {
			_, err := s.CurrentWorkspace(ctx)
			return err
		}, ErrNoCurrentWorkspace, "stack_profile::no_current_workspace"},
		{"a workspace with no directory", func() error {
			return s.SetCurrentWorkspace(ctx, "CCCCCCCCCCCCCCCC")
		}, ErrWorkspaceNotFound, "stack_profile::workspace_not_found"},
		{"a workspace id that is a path", func() error {
			return s.SetCurrentWorkspace(ctx, "../escape")
		}, ErrInvalidWorkspaceID, "stack_profile::invalid_workspace_id"},
		{"a file that is not there", func() error {
			_, err := ws.Token(ctx)
			return err
		}, ErrNotFound, "stack_profile::not_found"},
		{"a file that is not JSON", func() error {
			write(t, filepath.Join(dir, "workspaces", wsB, "auth.json"), "{not json")
			_, err := ws.Token(ctx)
			return err
		}, ErrInvalid, "stack_profile::json"},
		{"a file that is a directory", func() error {
			if err := os.MkdirAll(filepath.Join(dir, "workspaces", wsB, "secretkey.json"), 0o700); err != nil {
				t.Fatal(err)
			}
			_, _, err := ws.SecretKey(ctx)
			return err
		}, ErrIO, "stack_profile::io"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			wantCode(t, err, tc.code)
		})
	}
}

// A profile file that is not JSON says where: the line and column, never
// the parser's message, which could quote the file.
func TestAProfileJSONErrorNamesTheLine(t *testing.T) {
	ctx := context.Background()
	dir, s := profile(t)
	write(t, filepath.Join(dir, "workspaces", wsB, "auth.json"), "{\n  \"access_token\": 7\n}")
	ws, err := s.WorkspaceStore(ctx, wsB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ws.Token(ctx)
	d := wantDiagnostic(t, err, "stack_profile::json")
	if d.Fields["line"] != uint64(2) {
		t.Errorf("fields = %v, want line 2", d.Fields)
	}
	if d.Help == "" {
		t.Error("a JSON error gives no help")
	}
}
