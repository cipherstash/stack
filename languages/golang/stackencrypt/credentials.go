package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/cipherstash/cipherstash-suite/bindings/go/stackauth"
)

// Credentials is where a [Client]'s ZeroKMS credentials come from: the
// client id, the client key, and the stackauth strategy that supplies the
// bearer token. NewClient resolves them once, host-side — the crypto guest
// is never given the environment or a filesystem to look them up itself —
// and hands the key to the guest.
//
// [AutoCredentials] is the default: the environment, then the developer
// profile, in the Rust client's order. [NewCredentials] takes a client id,
// a client key and a strategy explicitly; [OIDCFederation] mints the token
// from an identity provider's. Those three are the only implementations:
// the interface is sealed, so a bearer token always comes from a stackauth
// strategy. A raw token cannot be refreshed when it expires, and a source
// outside the strategies would bypass the cross-process refresh lock the
// device session shares with the CLI (a refresh token used twice gets the
// whole chain revoked).
type Credentials interface {
	// resolve produces the credentials for one client. NewClient calls it
	// once, and consumes the key it returns. A result returned alongside
	// an error is consumed too: its key is wiped and its Close is called,
	// so an implementation may hand back what it built before it failed
	// rather than release it itself.
	resolve(ctx context.Context, opts resolveOptions) (*resolvedCredentials, error)
}

// resolveOptions is what NewClient tells a [Credentials] about the client
// it is resolving for, so a source that makes requests or holds key
// material of its own can do so under the client's settings.
type resolveOptions struct {
	// Transport is the client's RoundTripper (never nil). AutoCredentials
	// sends its authentication requests through it too.
	Transport http.RoundTripper
	// RequireLockedMemory is the client's setting. AutoCredentials applies
	// it to the credential guest, which holds the client key while it
	// reads it and the token strategy for the life of the client.
	RequireLockedMemory bool
}

// resolvedCredentials is one client's credentials, as a [Credentials]
// resolved them.
type resolvedCredentials struct {
	// ClientID is the ZeroKMS client id (a UUID string).
	ClientID string
	// ClientKey is the client key. NewClient consumes it whatever the
	// outcome, as [NewClientKey] describes.
	ClientKey *ClientKey
	// Token supplies the bearer token for every request: a stackauth
	// strategy, outside the package's own tests.
	Token tokenSource
	// Close, when not nil, releases what the credentials hold open — the
	// profile's guest and a refreshing token strategy, for AutoCredentials.
	// The client calls it from Client.Close, or from NewClient when the
	// client is not made. A Token that outlives it must not be asked again.
	Close func() error
	// MemoryLockError, when not nil, reports why memory the credentials
	// hold key material in is not locked in RAM: for AutoCredentials, the
	// credential guest's, which the client key passed through and the
	// token strategy lives in, as stackauth's ProfileStore.MemoryLockError
	// reports it. It is asked each time, not once: under best-effort
	// locking a guest's memory can become unlocked later, when a growth
	// for a token exchange or a refresh cannot be locked. The client folds
	// its answer into Client.MemoryLocked and Client.MemoryLockError, so a
	// checklist asserting the lock sees every guest the key was in, not
	// only the crypto guest. Nil, or returning nil, when the memory is
	// locked or the credentials hold nothing.
	MemoryLockError func() error
}

// ErrNoCredentials is [AutoCredentials] finding no token strategy or no
// client key in either place it looks. The wrapped error says which, and
// what to set.
var ErrNoCredentials = errors.New("stackencrypt: no credentials")

// NewCredentials is [Credentials] from explicit values: a client id, a
// client key (from [NewClientKey], or stackauth's typed read), and the
// stackauth strategy that supplies the bearer token (ProfileStore's
// AccessKey, DeviceSession, OIDC or Auto). The key is consumed by the first
// NewClient given these credentials; a second is refused with
// [ErrCredentialsConsumed], as a key is for one client. A nil strategy is
// refused by NewClient.
//
// The caller opened the strategy's ProfileStore and the strategy, and keeps
// them: the client asks the strategy for a token on every ZeroKMS request
// but never closes it or the store. Both must stay open until Client.Close
// has returned, and are the caller's to close after it — the strategy, then
// the store (closing the store closes its strategies too). A token asked of
// a closed strategy is an error from the operation that needed it.
func NewCredentials(clientID string, key *ClientKey, strategy *stackauth.Strategy) Credentials {
	c := &explicitCredentials{clientID: clientID, key: key}
	// A nil *Strategy stored in the interface would be a non-nil source
	// that fails on first use; left unset, resolve refuses it up front.
	if strategy != nil {
		c.token = strategy
	}
	return c
}

// ErrCredentialsConsumed is [NewCredentials] given to a second NewClient:
// the first consumed its key — whether it made a client or refused its
// config — so there is nothing left to give. Build new credentials, with a
// new key, for another client.
var ErrCredentialsConsumed = errors.New("stackencrypt: the credentials' client key was already consumed by an earlier NewClient")

// explicitCredentials is NewCredentials. token is the strategy; only this
// package's tests put anything else in it.
type explicitCredentials struct {
	clientID string
	key      *ClientKey
	token    tokenSource
	// consumed is set by the first resolve: what it handed out is the
	// caller's to wipe, and a second caller must not be told its values
	// were missing when they were spent.
	consumed atomic.Bool
}

func (c *explicitCredentials) resolve(context.Context, resolveOptions) (*resolvedCredentials, error) {
	if !c.consumed.CompareAndSwap(false, true) {
		return nil, ErrCredentialsConsumed
	}
	resolved := &resolvedCredentials{ClientID: c.clientID, ClientKey: c.key, Token: c.token}
	if c.token == nil {
		// Returned with the key, so NewClient consumes it as it does on
		// every other refusal.
		return resolved, fmt.Errorf("%w: NewCredentials needs a stackauth strategy for the token", ErrEncoding)
	}
	// No Close: the strategy and its store are the caller's.
	return resolved, nil
}

// String names the credentials' kind and client id; the key prints a
// redaction under every verb anyway, but nothing here asks it to.
func (c *explicitCredentials) String() string {
	return fmt.Sprintf("stackencrypt.NewCredentials{client_id: %s}", c.clientID)
}

// The environment variables AutoCredentials and NewClient read. The profile
// directory's own, CS_CONFIG_PATH, is stackauth's; so is CS_CTS_HOST, which
// its strategies take as the authentication endpoint.
const (
	envClientID     = "CS_CLIENT_ID"
	envClientKey    = "CS_CLIENT_KEY"
	envAccessKey    = "CS_CLIENT_ACCESS_KEY"
	envWorkspaceCRN = "CS_WORKSPACE_CRN"
)

// envZeroKMSHost is the endpoint override, in the order stack-kms reads it:
// the first that is set decides, and CS_VITUR_HOST is the legacy name.
var envZeroKMSHost = []string{"CS_ZEROKMS_HOST", "CS_VITUR_HOST"}

// AutoCredentials is [Credentials] from the environment first, then the
// developer profile `stash auth login` writes — the order the Rust client
// (stack-encrypt's StackCipher::builder().init()) resolves them in, so one
// set of variables configures a service in either language:
//
//   - The token, by stack-auth's AutoStrategy order: CS_CLIENT_ACCESS_KEY
//     (with CS_WORKSPACE_CRN, which is then required) exchanged for a token;
//     else the current workspace's stored device session, refreshed under
//     the same cross-process lock as the CLI. CS_CTS_HOST overrides the
//     authentication endpoint.
//   - The client key: CS_CLIENT_ID and CS_CLIENT_KEY when both are set (the
//     hex form, or the base64 of secretkey.json); else the current
//     workspace's secretkey.json. Only one of the two set is the same as
//     neither. Set but empty is an error, not a fall-through.
//
// The profile is CS_CONFIG_PATH, else ~/.cipherstash; a profile that cannot
// be opened is not an error — an environment-only deployment has none — it
// just leaves the environment as the only source, as the Rust client does.
// Nothing found in either place is [ErrNoCredentials], and when the profile
// would have been consulted, that error says why it could not be: a
// directory that does not exist, one that cannot be read, a path that is
// not a directory.
//
// The profile and the token strategies run in stackauth's credential guest,
// not in the crypto guest, which still sees no environment and no
// filesystem. The credential guest lives as long as the client, and
// Client.Close releases it.
func AutoCredentials() Credentials { return autoCredentials{} }

type autoCredentials struct{}

// String names the credentials' kind; nothing is resolved to print it.
func (autoCredentials) String() string { return "stackencrypt.AutoCredentials" }

func (autoCredentials) resolve(ctx context.Context, opts resolveOptions) (*resolvedCredentials, error) {
	return resolveWithStrategy(ctx, opts, func(ctx context.Context, profile *stackauth.ProfileStore, noProfile error) (*stackauth.Strategy, error) {
		strategy, err := profile.Auto(ctx)
		switch {
		case errors.Is(err, stackauth.ErrNotAuthenticated):
			if noProfile != nil {
				err = fmt.Errorf("%w: %w", err, noProfile)
			}
			return nil, fmt.Errorf("%w: no token: set %s and %s, or run `stash auth login`: %w",
				ErrNoCredentials, envAccessKey, envWorkspaceCRN, err)
		case errors.Is(err, stackauth.ErrAuthConfig) && accessKeyConfigured():
			// The status covers every configuration fault the guest reports;
			// name the variables only when they are what was configured.
			return nil, fmt.Errorf("stackencrypt: credentials: check %s and %s: %w", envAccessKey, envWorkspaceCRN, err)
		case err != nil:
			return nil, fmt.Errorf("stackencrypt: credentials: %w", err)
		}
		return strategy, nil
	})
}

// OIDCFederation is [Credentials] whose token is minted by federation: CTS
// exchanges a token from the application's own identity provider (Clerk,
// Auth0, Okta, a cloud workload identity) for a CipherStash one in the
// workspace crn names. provider is asked for a fresh IdP token only when a
// CipherStash token has to be minted; stackauth.OAuth2TokenSource adapts a
// golang.org/x/oauth2 source. The client key is resolved as
// [AutoCredentials] resolves it: CS_CLIENT_ID and CS_CLIENT_KEY, else the
// developer profile. CS_CTS_HOST overrides the authentication endpoint.
func OIDCFederation(crn string, provider stackauth.OIDCProvider) Credentials {
	return oidcCredentials{crn: crn, provider: provider}
}

type oidcCredentials struct {
	crn      string
	provider stackauth.OIDCProvider
}

// String names the credentials' kind and workspace; the provider is not
// asked for anything to print it.
func (c oidcCredentials) String() string {
	return fmt.Sprintf("stackencrypt.OIDCFederation{crn: %s}", c.crn)
}

func (c oidcCredentials) resolve(ctx context.Context, opts resolveOptions) (*resolvedCredentials, error) {
	return resolveWithStrategy(ctx, opts, func(ctx context.Context, profile *stackauth.ProfileStore, _ error) (*stackauth.Strategy, error) {
		strategy, err := profile.OIDC(ctx, c.crn, c.provider)
		if err != nil {
			return nil, fmt.Errorf("stackencrypt: credentials: OIDC federation: %w", err)
		}
		return strategy, nil
	})
}

// resolveWithStrategy opens the credential guest — over the profile when
// there is one, with nothing mounted when there is not — asks strategy for
// the token source (passing why there is no profile, when there is none),
// then resolves the client key from the environment or
// the profile. On success the guest and the strategy are the resolved
// credentials' to close; on failure they are closed here.
func resolveWithStrategy(
	ctx context.Context,
	opts resolveOptions,
	strategy func(ctx context.Context, profile *stackauth.ProfileStore, noProfile error) (*stackauth.Strategy, error),
) (_ *resolvedCredentials, err error) {
	authOpts := []stackauth.Option{stackauth.WithRoundTripper(opts.Transport)}
	if opts.RequireLockedMemory {
		authOpts = append(authOpts, stackauth.RequireLockedMemory())
	}
	profile, err := stackauth.Resolve(ctx, authOpts...)
	// noProfile is why there is no profile to consult, when there is none:
	// kept for the errors that would have consulted it, so a profile that
	// exists but cannot be opened is not reported as "not logged in".
	var noProfile error
	if errors.Is(err, stackauth.ErrNoProfile) {
		// The strategies that need no profile still run, in a guest with
		// nothing mounted; every profile read on it is ErrNoProfile.
		noProfile = err
		profile, err = stackauth.OpenWithoutProfile(ctx, authOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("stackencrypt: credentials: %w", err)
	}
	defer func() {
		if err != nil {
			_ = profile.Close()
		}
	}()

	// The token first, as Rust detects its strategy before it asks the key
	// provider: with neither configured, the error names the token.
	token, err := strategy(ctx, profile, noProfile)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = token.Close()
		}
	}()

	clientID, key, err := clientKeyFromEnv()
	if err != nil {
		return nil, err
	}
	if key == nil {
		if clientID, key, err = clientKeyFromProfile(ctx, profile, noProfile); err != nil {
			return nil, err
		}
	}
	return &resolvedCredentials{
		ClientID:  clientID,
		ClientKey: key,
		Token:     token,
		Close: func() error {
			// The strategy lives in the profile's guest, which closing the
			// profile would free anyway; closing it first unregisters it
			// cleanly.
			return errors.Join(token.Close(), profile.Close())
		},
		MemoryLockError: profile.MemoryLockError,
	}, nil
}

// accessKeyConfigured reports whether either variable of the access-key
// strategy is set: what its configuration errors are then about.
func accessKeyConfigured() bool {
	_, keySet := os.LookupEnv(envAccessKey)
	_, crnSet := os.LookupEnv(envWorkspaceCRN)
	return keySet || crnSet
}

// clientKeyFromEnv is stack-kms's EnvKeyProvider: both variables set is the
// key, either unset is no key (nil, and the profile is asked), and a set but
// empty value is an error, since falling through would quietly use a
// different key from the one the operator configured. The value is never
// part of an error.
func clientKeyFromEnv() (string, *ClientKey, error) {
	id, ok := os.LookupEnv(envClientID)
	if !ok {
		return "", nil, nil
	}
	material, ok := os.LookupEnv(envClientKey)
	if !ok {
		return "", nil, nil
	}
	if id == "" || material == "" {
		return "", nil, fmt.Errorf("%w: %s and %s are set, but one of them is empty", ErrEncoding, envClientID, envClientKey)
	}
	// The environment's string is Go's and cannot be wiped; this copy can,
	// and the ClientKey owns it.
	return id, NewClientKey([]byte(material)), nil
}

// clientKeyFromProfile is the current workspace's secretkey.json. The
// "nothing there" answers — no profile, no current workspace, no file — are
// ErrNoCredentials; a file that is there but unreadable keeps its own error.
// noProfile, when not nil, is why the profile could not be opened; the
// store's own answer to a read is then a bare ErrNoProfile, and the reason
// is the useful one.
func clientKeyFromProfile(ctx context.Context, profile *stackauth.ProfileStore, noProfile error) (string, *ClientKey, error) {
	notConfigured := func(err error) error {
		return fmt.Errorf("%w: no client key: set %s and %s, or run `stash auth login`: %w",
			ErrNoCredentials, envClientID, envClientKey, err)
	}
	workspace, err := profile.CurrentWorkspaceStore(ctx)
	if errors.Is(err, stackauth.ErrNoProfile) && noProfile != nil {
		err = noProfile
	}
	if errors.Is(err, stackauth.ErrNoProfile) || errors.Is(err, stackauth.ErrNoCurrentWorkspace) {
		return "", nil, notConfigured(err)
	}
	if err != nil {
		return "", nil, fmt.Errorf("stackencrypt: credentials: %w", err)
	}
	clientID, key, err := workspace.SecretKey(ctx)
	if errors.Is(err, stackauth.ErrNotFound) {
		return "", nil, notConfigured(err)
	}
	if err != nil {
		return "", nil, fmt.Errorf("stackencrypt: credentials: reading the client key: %w", err)
	}
	return clientID, key, nil
}

// zerokmsEndpoint is the endpoint NewClient pins, in stack-kms's order: the
// explicit URL, else the first of CS_ZEROKMS_HOST and CS_VITUR_HOST that is
// set, else none (the token's services claim decides on first use). A set
// variable that is not a usable endpoint is an error, not a fall-through:
// falling through would send key operations somewhere the operator did not
// configure. The guest validates the URL in full; this check exists to name
// the variable, and never prints the value, which could carry userinfo.
func zerokmsEndpoint(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	for _, name := range envZeroKMSHost {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		u, err := url.Parse(value)
		switch {
		case err != nil:
			return "", fmt.Errorf("%w: %s is not a URL", ErrEncoding, name)
		case u.Scheme != "http" && u.Scheme != "https":
			return "", fmt.Errorf("%w: %s must be an http or https URL", ErrEncoding, name)
		case u.Host == "":
			return "", fmt.Errorf("%w: %s has no host", ErrEncoding, name)
		}
		return value, nil
	}
	return "", nil
}
