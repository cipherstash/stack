package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials from the developer profile `stash auth login` writes.
//
// The Go binding takes a client key and a bearer token explicitly. The
// profile fallback in the Rust crate is native-only — stack-kms gates it off
// wasm32 and the guest is wasm — so a Go program reads the profile itself,
// which is all this file does. There is no supported package-level
// equivalent yet; see the README.
//
// The layout, as stack-profile defines it:
//
//	<root>/current_workspace                          the workspace id
//	<root>/workspaces/<id>/secretkey.json             client_id, client_key
//	<root>/workspaces/<id>/auth.json                  access_token, expires_at
//
// where <root> is CS_CONFIG_PATH if set, else ~/.cipherstash.
type credentials struct {
	ClientID  string
	ClientKey string
	Workspace string
	dir       string
}

type secretKeyFile struct {
	ClientID  string `json:"client_id"`
	ClientKey string `json:"client_key"`
}

type authFile struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
	Region      string `json:"region"`
}

func loadCredentials() (credentials, error) {
	var c credentials

	root := os.Getenv("CS_CONFIG_PATH")
	if strings.TrimSpace(root) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return c, fmt.Errorf("no home directory and CS_CONFIG_PATH is unset: %w", err)
		}
		root = filepath.Join(home, ".cipherstash")
	}

	workspace, err := os.ReadFile(filepath.Join(root, "current_workspace"))
	if err != nil {
		return c, fmt.Errorf("no current workspace in %s — run `stash auth login`: %w", root, err)
	}
	c.Workspace = strings.TrimSpace(string(workspace))
	if !validWorkspaceID(c.Workspace) {
		return c, fmt.Errorf("current_workspace in %s is not a workspace id (%q) — run `stash auth login`", root, c.Workspace)
	}
	c.dir = filepath.Join(root, "workspaces", c.Workspace)

	// The client key: the two environment variables win, as they do for the
	// Rust client, so this example can be pointed somewhere else without
	// touching the profile.
	c.ClientID, c.ClientKey = os.Getenv("CS_CLIENT_ID"), os.Getenv("CS_CLIENT_KEY")
	if c.ClientID == "" || c.ClientKey == "" {
		var key secretKeyFile
		if err := readJSON(filepath.Join(c.dir, "secretkey.json"), &key); err != nil {
			return c, fmt.Errorf("no client key — set CS_CLIENT_ID and CS_CLIENT_KEY, or run `stash auth login`: %w", err)
		}
		c.ClientID, c.ClientKey = key.ClientID, key.ClientKey
	}

	// Fail here rather than three calls later, with something actionable.
	if _, err := c.token().Token(context.Background()); err != nil {
		return c, err
	}
	return c, nil
}

// token is the [stackencrypt.TokenSource] this example authenticates with.
//
// Deliberately not StaticToken: the binding asks its TokenSource on *every*
// request precisely so that a token can change under a long-lived client,
// and a profile token is good for 45 minutes. A static one turns that into
// a program that works and then stops, which is the wrong thing to show.
//
// What it does instead is *follow* the profile: it re-reads auth.json each
// time, so whatever keeps the profile fresh — the `stash` CLI, a Rust
// client in the same session — is picked up without restarting.
//
// What it deliberately does not do is refresh. Exchanging the refresh token
// is not a few lines: the IdP rotates refresh tokens and detects replay, so
// two processes sharing ~/.cipherstash that both exchange the same one get
// the whole chain revoked — every later login fails with "invalid grant"
// until the user logs in again. The Rust side handles that with a
// cross-process lock and a re-read after acquiring it
// (stack-auth's `device_session_refresher`). An example that hand-rolled it
// would risk a reader's real credentials, so this one reads and never
// writes.
func (c credentials) token() stackencryptTokenSource {
	return stackencryptTokenSource{path: filepath.Join(c.dir, "auth.json")}
}

type stackencryptTokenSource struct{ path string }

func (s stackencryptTokenSource) Token(context.Context) (string, error) {
	var auth authFile
	if err := readJSON(s.path, &auth); err != nil {
		return "", fmt.Errorf("no access token in %s — run `stash auth login`: %w", s.path, err)
	}
	if expiry := time.Unix(auth.ExpiresAt, 0); time.Now().After(expiry) {
		return "", fmt.Errorf("the profile's access token expired at %s — run `stash auth login`",
			expiry.Format(time.RFC3339))
	}
	return auth.AccessToken, nil
}

// describe reports what the profile currently holds, for the banner.
func (c credentials) describe() string {
	var auth authFile
	if err := readJSON(filepath.Join(c.dir, "auth.json"), &auth); err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%s, token good for %s",
		auth.Region, time.Until(time.Unix(auth.ExpiresAt, 0)).Round(time.Minute))
}

// validWorkspaceID is stack-profile's rule for a workspace id: sixteen
// base32 characters (A-Z, 2-7). The id becomes a path component under
// workspaces/, and current_workspace is a plain file anything can write, so
// it is checked here as the Rust reader checks it — otherwise "../.." in that
// file reads credentials from outside the profile.
func validWorkspaceID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(('A' <= c && c <= 'Z') || ('2' <= c && c <= '7')) {
			return false
		}
	}
	return true
}

func readJSON(path string, into any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}
