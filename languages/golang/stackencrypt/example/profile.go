package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials from the developer profile `stash auth login` writes.
//
// The Go binding takes a client key and a bearer token explicitly: the
// profile fallback in the Rust crate is native-only (stack-kms gates it off
// wasm32), and the guest is wasm. So a Go program reads the profile itself,
// which is all this file does.
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
	Token     string
	Workspace string
	Region    string
	ExpiresAt time.Time
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
	dir := filepath.Join(root, "workspaces", c.Workspace)

	// The client key: the two environment variables win, as they do for the
	// Rust client, so this example can be pointed somewhere else without
	// touching the profile.
	c.ClientID, c.ClientKey = os.Getenv("CS_CLIENT_ID"), os.Getenv("CS_CLIENT_KEY")
	if c.ClientID == "" || c.ClientKey == "" {
		var key secretKeyFile
		if err := readJSON(filepath.Join(dir, "secretkey.json"), &key); err != nil {
			return c, fmt.Errorf("no client key — set CS_CLIENT_ID and CS_CLIENT_KEY, or run `stash auth login`: %w", err)
		}
		c.ClientID, c.ClientKey = key.ClientID, key.ClientKey
	}

	// The token comes from the profile only. There is no environment
	// variable for it: CS_CLIENT_ACCESS_KEY is an access *key*, which has to
	// be exchanged for a bearer token first, and this example does not do
	// that exchange.
	var auth authFile
	if err := readJSON(filepath.Join(dir, "auth.json"), &auth); err != nil {
		return c, fmt.Errorf("no access token in %s — run `stash auth login`: %w", dir, err)
	}
	c.Token, c.Region = auth.AccessToken, auth.Region
	c.ExpiresAt = time.Unix(auth.ExpiresAt, 0)
	if time.Now().After(c.ExpiresAt) {
		return c, fmt.Errorf("the profile's access token expired at %s — run `stash auth login`", c.ExpiresAt.Format(time.RFC3339))
	}
	return c, nil
}

func readJSON(path string, into any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}
