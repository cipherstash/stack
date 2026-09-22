package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cipherstash/cipherstash-suite/bindings/go/stackauth"
	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
)

// Credentials from the developer profile `stash auth login` writes, read
// through stackauth: the stack-profile crate itself, running in the
// credential guest, so nothing here spells the profile's layout. (An
// earlier version of this file read ~/.cipherstash by hand, which is the
// drift stackauth exists to end.)
type credentials struct {
	ClientID  string
	ClientKey *stackencrypt.ClientKey
	Workspace string
	// profile owns the guest; Close releases it. The workspace store shares
	// it and is closed with it.
	profile   *stackauth.ProfileStore
	workspace *stackauth.ProfileStore
}

func loadCredentials(ctx context.Context) (*credentials, error) {
	// CS_CONFIG_PATH, else ~/.cipherstash, as the Rust crate resolves it.
	profile, err := stackauth.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	c := &credentials{profile: profile}
	if c.workspace, err = profile.CurrentWorkspaceStore(ctx); err != nil {
		profile.Close()
		return nil, fmt.Errorf("no current workspace — run `stash auth login`: %w", err)
	}
	if c.Workspace, err = profile.CurrentWorkspace(ctx); err != nil {
		profile.Close()
		return nil, err
	}

	// The client key: the two environment variables win, as they do for the
	// Rust client, so this example can be pointed somewhere else without
	// touching the profile. Otherwise it is the workspace's secretkey.json,
	// handed out as the opaque ClientKey a stackencrypt.Config takes.
	if id, key := os.Getenv("CS_CLIENT_ID"), os.Getenv("CS_CLIENT_KEY"); id != "" && key != "" {
		c.ClientID, c.ClientKey = id, stackencrypt.NewClientKey([]byte(key))
	} else if c.ClientID, c.ClientKey, err = c.workspace.SecretKey(ctx); err != nil {
		profile.Close()
		return nil, fmt.Errorf("no client key — set CS_CLIENT_ID and CS_CLIENT_KEY, or run `stash auth login`: %w", err)
	}

	// Fail here rather than three calls later, with something actionable:
	// an expired stored token names `stash auth login`.
	if _, err := c.token().Token(ctx); err != nil {
		profile.Close()
		return nil, err
	}
	return c, nil
}

// Close releases the profile guest, and with it the workspace store.
func (c *credentials) Close() error { return c.profile.Close() }

// token is the [stackencrypt.TokenSource] this example authenticates with:
// stackauth's, over the workspace's auth.json.
//
// Deliberately not StaticToken: the binding asks its TokenSource on *every*
// request precisely so that a token can change under a long-lived client,
// and a profile token is good for 45 minutes. A static one turns that into
// a program that works and then stops, which is the wrong thing to show.
// stackauth's source re-reads auth.json each time, so whatever keeps the
// profile fresh — the `stash` CLI, a Rust client in the same session — is
// picked up without restarting, and it refuses a token at its real expiry.
//
// What it does not do yet is refresh. Exchanging the refresh token is the
// auth half of stackauth: the IdP rotates refresh tokens and detects
// replay, so two processes sharing ~/.cipherstash that both exchange the
// same one get the whole chain revoked, and the Rust side handles that
// with a cross-process lock and a re-read after acquiring it. Until that
// half lands, an expired token means `stash auth login`.
func (c *credentials) token() stackencrypt.TokenSource { return c.workspace.TokenSource() }

// describe reports what the profile currently holds, for the banner.
func (c *credentials) describe(ctx context.Context) string {
	tok, err := c.workspace.Token(ctx)
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%s, token good for %s", tok.Region, time.Until(tok.ExpiresAt).Round(time.Minute))
}
