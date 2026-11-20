package encrypt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// ClientKeySource is where credentials read the ZeroKMS client id and
// client key. Give one to [OIDCFederationCredentials.WithClientKey]:
//
//   - [ClientKeyFromEnv] reads CS_CLIENT_ID and CS_CLIENT_KEY.
//   - [ClientKeyFromProfile] reads the key that `stash auth login` saved for
//     the workspace you name.
//   - [ClientKeyFromValues] takes a client id and a client key that your
//     program loaded.
//
// The client key must belong to the workspace that the tokens are for.
// ZeroKMS refuses a request whose token and client key come from different
// workspaces.
//
// Those three are the only implementations: the interface is sealed.
type ClientKeySource interface {
	// readClientKey returns the client id and the client key. profile is
	// the credential guest's store. noProfile, when not nil, is why the
	// store has no profile directory mounted. The caller consumes the key.
	readClientKey(ctx context.Context, profile *auth.ProfileStore, noProfile error) (clientID string, key *ClientKey, err error)
	// usesProfile reports whether readClientKey reads the developer
	// profile. When no source in use reads it, the credential guest is
	// opened with no directory mounted.
	usesProfile() bool
}

// ClientKeyFromEnv is a [ClientKeySource] that reads CS_CLIENT_ID and
// CS_CLIENT_KEY. CS_CLIENT_KEY holds the key in hex, or the base64 encoding
// of secretkey.json.
//
// It reads nothing else. If either variable is unset, NewClient returns
// [ErrNoCredentials]. If both are set and either is empty, NewClient
// returns [ErrEncoding]. Neither error contains the key.
func ClientKeyFromEnv() ClientKeySource { return envKeySource{} }

type envKeySource struct{}

// String names the source; nothing is read to print it.
func (envKeySource) String() string { return "encrypt.ClientKeyFromEnv" }

func (envKeySource) usesProfile() bool { return false }

func (envKeySource) readClientKey(context.Context, *auth.ProfileStore, error) (string, *ClientKey, error) {
	clientID, key, err := clientKeyFromEnv()
	if err == nil && key == nil {
		err = fmt.Errorf("%w: no client key: set %s and %s", ErrNoCredentials, envClientID, envClientKey)
	}
	return clientID, key, err
}

// ClientKeyFromProfile is a [ClientKeySource] that reads secretkey.json of
// the workspace that workspaceCRN names. `stash auth login` writes one
// secretkey.json for each workspace, in the profile directory:
// CS_CONFIG_PATH, else ~/.cipherstash.
//
// The key is always the named workspace's. If that workspace has no
// secretkey.json on this machine, NewClient returns [ErrNoCredentials]. It
// does not read the CLI's current workspace, or any other workspace, in its
// place. It does not read the environment.
//
// An empty workspaceCRN is [ErrEncoding]. A workspaceCRN that is not a
// workspace CRN is auth.ErrConfig.
func ClientKeyFromProfile(workspaceCRN string) ClientKeySource {
	return profileKeySource{crn: workspaceCRN}
}

type profileKeySource struct{ crn string }

// String names the source and the workspace; nothing is read to print it.
func (k profileKeySource) String() string {
	return fmt.Sprintf("encrypt.ClientKeyFromProfile{crn: %s}", k.crn)
}

func (profileKeySource) usesProfile() bool { return true }

func (k profileKeySource) validate() error {
	if strings.TrimSpace(k.crn) == "" {
		return fmt.Errorf("%w: ClientKeyFromProfile needs the workspace CRN", ErrEncoding)
	}
	return nil
}

func (k profileKeySource) readClientKey(ctx context.Context, profile *auth.ProfileStore, noProfile error) (string, *ClientKey, error) {
	if err := k.validate(); err != nil {
		return "", nil, err
	}
	return clientKeyFromWorkspace(ctx, profile, noProfile, k.crn,
		"run `stash auth login` for the workspace "+k.crn)
}

// ClientKeyFromValues is a [ClientKeySource] that holds a client id and a
// client key your program loaded. It reads neither the environment nor the
// developer profile.
//
// The key is consumed by the first NewClient given credentials with this
// source, whatever the outcome; a second is refused with
// [ErrCredentialsConsumed]. A key is for one client. An empty client id or a
// nil key is [ErrEncoding].
//
// Wrap key material that is in a string with [NewClientKey]:
//
//	key := encrypt.ClientKeyFromValues(cfg.ClientID, encrypt.NewClientKey([]byte(cfg.ClientKey)))
//
// A Go string cannot be wiped, so a key kept in one stays in memory as long
// as the string does. NewClient wipes the [ClientKey].
func ClientKeyFromValues(clientID string, key *ClientKey) ClientKeySource {
	return &valuesKeySource{clientID: clientID, key: key}
}

type valuesKeySource struct {
	clientID string
	key      *ClientKey
	// consumed is set when the key is handed out or wiped unused.
	consumed atomic.Bool
}

// String names the source and the client id. The key prints a redaction
// under every verb anyway, but nothing here asks it to.
func (k *valuesKeySource) String() string {
	return fmt.Sprintf("encrypt.ClientKeyFromValues{client_id: %s}", k.clientID)
}

func (*valuesKeySource) usesProfile() bool { return false }

func (k *valuesKeySource) validate() error {
	switch {
	case k.consumed.Load():
		return ErrCredentialsConsumed
	case strings.TrimSpace(k.clientID) == "":
		return fmt.Errorf("%w: ClientKeyFromValues needs a client id", ErrEncoding)
	case k.key == nil:
		return fmt.Errorf("%w: ClientKeyFromValues needs a client key", ErrEncoding)
	}
	return nil
}

func (k *valuesKeySource) readClientKey(context.Context, *auth.ProfileStore, error) (string, *ClientKey, error) {
	if !k.consumed.CompareAndSwap(false, true) {
		return "", nil, ErrCredentialsConsumed
	}
	return k.clientID, k.key, nil
}

// discard wipes a key that was never handed out, and marks it consumed.
func (k *valuesKeySource) discard() {
	k.consumed.Store(true)
	k.key.Wipe()
}

// envThenProfileKeySource is OIDCFederation's default: CS_CLIENT_ID and
// CS_CLIENT_KEY when both are set, else secretkey.json of the workspace crn
// names. It is the workspace the tokens are for, so the key never comes
// from another workspace.
type envThenProfileKeySource struct{ crn string }

func (envThenProfileKeySource) usesProfile() bool { return true }

func (k envThenProfileKeySource) readClientKey(ctx context.Context, profile *auth.ProfileStore, noProfile error) (string, *ClientKey, error) {
	clientID, key, err := clientKeyFromEnv()
	if err != nil || key != nil {
		return clientID, key, err
	}
	return clientKeyFromWorkspace(ctx, profile, noProfile, k.crn,
		fmt.Sprintf("set %s and %s, or run `stash auth login` for the workspace %s", envClientID, envClientKey, k.crn))
}

// autoKeySource is AutoCredentials' source: CS_CLIENT_ID and CS_CLIENT_KEY
// when both are set, else the current workspace's secretkey.json.
type autoKeySource struct{}

func (autoKeySource) usesProfile() bool { return true }

func (autoKeySource) readClientKey(ctx context.Context, profile *auth.ProfileStore, noProfile error) (string, *ClientKey, error) {
	clientID, key, err := clientKeyFromEnv()
	if err != nil || key != nil {
		return clientID, key, err
	}
	return clientKeyFromProfile(ctx, profile, noProfile)
}

// missingKeySource is what [OIDCFederationCredentials.WithClientKey] stores
// for a nil source. NewClient refuses it before it resolves anything.
type missingKeySource struct{}

func (missingKeySource) usesProfile() bool { return false }

func (missingKeySource) readClientKey(context.Context, *auth.ProfileStore, error) (string, *ClientKey, error) {
	return "", nil, errMissingClientKey
}

var errMissingClientKey = fmt.Errorf("%w: WithClientKey was given a nil ClientKeySource", ErrEncoding)

// validateClientKeySource runs the checks a source needs nothing resolved
// for. NewClient runs them host-side, before it loads a guest.
func validateClientKeySource(key ClientKeySource) error {
	switch k := key.(type) {
	case missingKeySource:
		return errMissingClientKey
	case profileKeySource:
		return k.validate()
	case *valuesKeySource:
		return k.validate()
	}
	return nil
}

// discardClientKey wipes key material a source holds from construction,
// when NewClient does not reach the point of reading it.
func discardClientKey(key ClientKeySource) {
	if k, ok := key.(*valuesKeySource); ok {
		k.discard()
	}
}

// clientKeyFromWorkspace is secretkey.json of the workspace crn names. The
// "nothing there" answers — no profile, no file — are ErrNoCredentials,
// with hint saying what to do. A file that is there but unreadable keeps its
// own error. noProfile, when not nil, is why the profile could not be
// opened.
func clientKeyFromWorkspace(ctx context.Context, profile *auth.ProfileStore, noProfile error, crn, hint string) (string, *ClientKey, error) {
	notConfigured := func(err error) error {
		return fmt.Errorf("%w: no client key: %s: %w", ErrNoCredentials, hint, err)
	}
	workspace, err := profile.WorkspaceStoreForCRN(ctx, crn)
	if errors.Is(err, auth.ErrNoProfile) && noProfile != nil {
		err = noProfile
	}
	switch {
	case errors.Is(err, auth.ErrNoProfile):
		return "", nil, notConfigured(err)
	case errors.Is(err, auth.ErrConfig):
		return "", nil, fmt.Errorf("encrypt: credentials: the client key's workspace CRN %q: %w", crn, err)
	case err != nil:
		return "", nil, fmt.Errorf("encrypt: credentials: %w", err)
	}
	clientID, key, err := workspace.SecretKey(ctx)
	if errors.Is(err, auth.ErrNotFound) {
		return "", nil, notConfigured(err)
	}
	if err != nil {
		return "", nil, fmt.Errorf("encrypt: credentials: reading the client key: %w", err)
	}
	return clientID, key, nil
}
