package encrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// Credentials is where a [Client]'s ZeroKMS credentials come from: the
// client id, the client key, and the auth strategy that supplies the
// bearer token. NewClient resolves them once, host-side — the crypto guest
// is never given the environment or a filesystem to look them up itself —
// and hands the key to the guest.
//
// [AutoCredentials] is the default: the environment, then the developer
// profile, in the Rust client's order. [AccessKeyCredentials] takes four
// values from a struct the program fills, with no fallback. [NewCredentials]
// takes a client id, a client key, and a strategy explicitly. [OIDCFederation]
// exchanges a token from an identity provider for a CipherStash token.
//
// Those four are the only implementations:
// the interface is sealed, so a bearer token always comes from an auth
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
	// Transport is the client's RoundTripper (never nil). AutoCredentials,
	// AccessKeyCredentials, and OIDCFederation send their authentication
	// requests through it too.
	Transport http.RoundTripper
	// RequireLockedMemory is the client's setting. AutoCredentials,
	// AccessKeyCredentials, and OIDCFederation apply it to the credential
	// guest. That guest contains the token strategy for the life of the
	// client. Under AutoCredentials it also contains the client key while
	// AutoCredentials reads it.
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
	// Token supplies the bearer token for every request: an auth
	// strategy, outside the package's own tests.
	Token tokenSource
	// Close, when not nil, releases what the credentials keep open. For
	// AutoCredentials, AccessKeyCredentials, and OIDCFederation, that is the
	// credential guest and its token strategy.
	// The client calls it from Client.Close, or from NewClient when the
	// client is not made. A Token that outlives it must not be asked again.
	Close func() error
	// MemoryLockError, when not nil, reports why memory the credentials
	// hold key material in is not locked in RAM: the credential guest's,
	// which the token strategy lives in and (for AutoCredentials and
	// OIDCFederation) the client key passed through. AutoCredentials,
	// AccessKeyCredentials, and OIDCFederation pass on their store's
	// ProfileStore.MemoryLockError;
	// NewCredentials, the caller's strategy's Strategy.MemoryLockError,
	// which is its store's. It is asked each time, not once: under
	// best-effort locking a guest's memory can become unlocked later, when
	// a growth for a token exchange or a refresh cannot be locked. NewClient
	// refuses the credentials with it under WithRequireLockedMemory, and the
	// client folds its answer into Client.MemoryLocked and
	// Client.MemoryLockError, so a checklist asserting the lock sees every
	// guest the key was in, not only the crypto guest. Nil, or returning
	// nil, when the memory is locked or the credentials hold nothing.
	MemoryLockError func() error
}

// ErrNoCredentials is [AutoCredentials] finding no token strategy or no
// client key in either place it looks. The wrapped error says which, and
// what to set.
var ErrNoCredentials = errors.New("encrypt: no credentials")

// NewCredentials is [Credentials] from explicit values: a client id, a
// client key (from [NewClientKey], or auth's typed read), and the
// auth strategy that supplies the bearer token (ProfileStore's
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
func NewCredentials(clientID string, key *ClientKey, strategy *auth.Strategy) Credentials {
	c := &explicitCredentials{clientID: clientID, key: key}
	// A nil *Strategy stored in the interface would be a non-nil source
	// that fails on first use; left unset, NewClient refuses it up front.
	if strategy != nil {
		c.token = strategy
	}
	return c
}

// ErrCredentialsConsumed is [NewCredentials] given to a second NewClient:
// the first consumed its key — whether it made a client or refused its
// config — so there is nothing left to give. Build new credentials, with a
// new key, for another client.
var ErrCredentialsConsumed = errors.New("encrypt: the credentials' client key was already consumed by an earlier NewClient")

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
	// A nil token never gets here: NewClient refuses it host-side, before
	// the guest is read.
	resolved := &resolvedCredentials{ClientID: c.clientID, ClientKey: c.key, Token: c.token}
	if strategy, ok := c.token.(*auth.Strategy); ok {
		// The strategy's store is the guest the token lives in and, when
		// the key was read through it, the key passed through: reported
		// live, as AutoCredentials reports its profile's.
		resolved.MemoryLockError = strategy.MemoryLockError
	}
	// No Close: the strategy and its store are the caller's.
	return resolved, nil
}

// String names the credentials' kind and client id; the key prints a
// redaction under every verb anyway, but nothing here asks it to.
func (c *explicitCredentials) String() string {
	return fmt.Sprintf("encrypt.NewCredentials{client_id: %s}", c.clientID)
}

// The environment variables AutoCredentials and NewClient read. The profile
// directory's own, CS_CONFIG_PATH, is auth's; so is CS_CTS_HOST, which
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
// The profile and the token strategies run in auth's credential guest,
// not in the crypto guest, which still sees no environment and no
// filesystem. The credential guest lives as long as the client, and
// Client.Close releases it.
func AutoCredentials() Credentials { return autoCredentials{} }

type autoCredentials struct{}

// String names the credentials' kind; nothing is resolved to print it.
func (autoCredentials) String() string { return "encrypt.AutoCredentials" }

func (autoCredentials) resolve(ctx context.Context, opts resolveOptions) (*resolvedCredentials, error) {
	return resolveWithStrategy(ctx, opts, func(ctx context.Context, profile *auth.ProfileStore, noProfile error) (*auth.Strategy, error) {
		strategy, err := profile.Auto(ctx)
		switch {
		case errors.Is(err, auth.ErrNotAuthenticated):
			if noProfile != nil {
				err = fmt.Errorf("%w: %w", err, noProfile)
			}
			return nil, fmt.Errorf("%w: no token: set %s and %s, or run `stash auth login`: %w",
				ErrNoCredentials, envAccessKey, envWorkspaceCRN, err)
		case errors.Is(err, auth.ErrConfig) && accessKeyConfigured():
			// The status covers every configuration fault the guest reports;
			// name the variables only when they are what was configured.
			return nil, fmt.Errorf("encrypt: credentials: check %s and %s: %w", envAccessKey, envWorkspaceCRN, err)
		case err != nil:
			return nil, fmt.Errorf("encrypt: credentials: %w", err)
		}
		return strategy, nil
	})
}

// OIDCFederation is [Credentials] whose token is minted by federation: CTS
// exchanges a token from the application's own identity provider (Clerk,
// Auth0, Okta, a cloud workload identity) for a CipherStash one in the
// workspace crn names. provider is asked on every token fetch for the IdP
// token of the user the call is for, and each distinct IdP token is
// exchanged once while its CipherStash token lasts, so one client serves
// many users without one user ever riding another's token;
// auth.OAuth2TokenSource adapts a golang.org/x/oauth2 source. The
// client key is resolved as
// [AutoCredentials] resolves it: CS_CLIENT_ID and CS_CLIENT_KEY, else the
// developer profile.
//
// opts configure the federation strategy as they would
// auth.ProfileStore.OIDC: auth.WithBaseURL pins the CTS
// endpoint for these credentials alone (without it, CS_CTS_HOST overrides
// the endpoint, else it is discovered), and auth.WithCacheCapacity
// sets how many users' tokens are kept (1024 unless set).
func OIDCFederation(crn string, provider auth.OIDCProvider, opts ...auth.StrategyOption) Credentials {
	return &oidcCredentials{crn: crn, provider: provider, opts: opts}
}

type oidcCredentials struct {
	crn      string
	provider auth.OIDCProvider
	opts     []auth.StrategyOption
}

// String names the credentials' kind and workspace; the provider is not
// asked for anything to print it.
func (c oidcCredentials) String() string {
	return fmt.Sprintf("encrypt.OIDCFederation{crn: %s}", c.crn)
}

func (c oidcCredentials) resolve(ctx context.Context, opts resolveOptions) (*resolvedCredentials, error) {
	return resolveWithStrategy(ctx, opts, func(ctx context.Context, profile *auth.ProfileStore, _ error) (*auth.Strategy, error) {
		strategy, err := profile.OIDC(ctx, c.crn, c.provider, c.opts...)
		if err != nil {
			return nil, fmt.Errorf("encrypt: credentials: OIDC federation: %w", err)
		}
		return strategy, nil
	})
}

// AccessKeyCredentials is [Credentials] from four values your program loads.
// The client id and client key identify your application to ZeroKMS.
// NewClient exchanges the client access key for a token. The token is for
// the workspace that WorkspaceCRN names.
//
// NewClient does not read the environment or the developer profile for
// these credentials. If a field is empty or blank, NewClient returns
// [ErrEncoding] and names the field.
//
// Each field has an env tag that names the variable [AutoCredentials] reads.
// github.com/sethvargo/go-envconfig and github.com/caarlos0/env both read
// tags in this form. Fill the struct on its own, or as a field of your
// configuration struct:
//
//	var creds encrypt.AccessKeyCredentials
//	if err := envconfig.Process(ctx, &creds); err != nil {
//		return err
//	}
//	client, err := encrypt.NewClient(ctx, encrypt.WithCredentials(creds))
//
// NewClient opens auth's credential guest for the token exchange. The guest
// has no files mounted, and uses the client's [WithTransport] and
// [WithRequireLockedMemory] settings. Client.Close releases the guest.
// CS_CTS_HOST and CS_ZEROKMS_HOST still override the endpoints, as they do
// for every Credentials.
//
// The two keys are [Secret] values. Printing, logging, or encoding the
// struct shows neither key. Keep the struct in an exported field of any
// configuration struct you print. fmt prints a value in an unexported field
// in full.
//
// A Go string cannot be wiped, so each key stays in memory as long as the
// struct does. NewClient wipes its own copy of the client key. A [ClientKey]
// can be wiped. If your program can keep the key as bytes, pass a ClientKey
// to [NewCredentials] instead.
type AccessKeyCredentials struct {
	// ClientID is the ZeroKMS client id. The id is a UUID (universally
	// unique identifier).
	ClientID string `env:"CS_CLIENT_ID,required"`
	// ClientKey is the client key, in hex. The base64 encoding of the
	// secretkey.json file that `stash auth login` writes also works.
	ClientKey Secret `env:"CS_CLIENT_KEY,required"`
	// ClientAccessKey is the client access key. NewClient exchanges it for
	// a bearer token.
	ClientAccessKey Secret `env:"CS_CLIENT_ACCESS_KEY,required"`
	// WorkspaceCRN is the CRN (Cloud Resource Name) of the workspace that
	// the client access key belongs to.
	WorkspaceCRN string `env:"CS_WORKSPACE_CRN,required"`
}

// Secret is a credential. fmt and slog print a Secret as [redacted], under
// every verb. Every encoder that uses [encoding.TextMarshaler] writes it as
// [redacted] too. Those encoders include the standard JSON and XML packages,
// and the common YAML and TOML libraries. Convert a Secret to a string to read it.
// A configuration loader fills a Secret as it fills any string field.
//
// fmt calls no method on a value in an unexported struct field. A Secret in
// an unexported field prints in full. That includes a Secret in a struct
// that is in an unexported field. Keep credentials in exported fields of
// anything you print or log.
//
// If you encode a Secret and decode it again, you get the text [redacted],
// not the key. NewClient refuses credentials that contain that text.
type Secret string

// String returns [redacted].
func (Secret) String() string { return redacted }

// GoString returns [redacted].
func (Secret) GoString() string { return redacted }

// Format prints [redacted] under every verb, %d and %#v included.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// LogValue logs [redacted].
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText returns [redacted]. The standard JSON and XML packages call
// it, and so do the other encoders that use [encoding.TextMarshaler].
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// validate refuses a field that is empty or only whitespace. The check also
// refuses a key that is the text [redacted]. A Secret contains that text
// after it is encoded and decoded again. The check resolves nothing, so
// NewClient runs it host-side, before it loads the guest.
func (c AccessKeyCredentials) validate() error {
	var blank, redactedKeys []string
	for _, field := range []struct{ name, env, value string }{
		{"ClientID", envClientID, c.ClientID},
		{"ClientKey", envClientKey, string(c.ClientKey)},
		{"ClientAccessKey", envAccessKey, string(c.ClientAccessKey)},
		{"WorkspaceCRN", envWorkspaceCRN, c.WorkspaceCRN},
	} {
		name := fmt.Sprintf("%s (%s)", field.name, field.env)
		switch {
		case strings.TrimSpace(field.value) == "":
			blank = append(blank, name)
		case field.value == redacted:
			redactedKeys = append(redactedKeys, name)
		}
	}
	if len(blank) > 0 {
		return fmt.Errorf("%w: AccessKeyCredentials: empty or blank: %s", ErrEncoding, strings.Join(blank, ", "))
	}
	if len(redactedKeys) > 0 {
		return fmt.Errorf("%w: AccessKeyCredentials: %s contains %s: the credentials were encoded and decoded again, and encoding redacts each key",
			ErrEncoding, strings.Join(redactedKeys, ", "), redacted)
	}
	return nil
}

func (c AccessKeyCredentials) resolve(ctx context.Context, opts resolveOptions) (_ *resolvedCredentials, err error) {
	// NewClient has run this check already. Running it again keeps resolve
	// safe to call on its own.
	if err := c.validate(); err != nil {
		return nil, err
	}
	store, err := openCredentialGuest(ctx, opts, auth.OpenWithoutProfile)
	if err != nil {
		return nil, credentialGuestError(err)
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()
	token, err := store.AccessKey(ctx, c.WorkspaceCRN, string(c.ClientAccessKey))
	switch {
	case errors.Is(err, auth.ErrConfig):
		return nil, fmt.Errorf("encrypt: credentials: check ClientAccessKey and WorkspaceCRN: %w", err)
	case err != nil:
		return nil, fmt.Errorf("encrypt: credentials: %w", err)
	}
	return &resolvedCredentials{
		ClientID: c.ClientID,
		// This copy can be wiped, and the ClientKey owns it.
		ClientKey: NewClientKey([]byte(c.ClientKey)),
		Token:     token,
		Close: func() error {
			return errors.Join(token.Close(), store.Close())
		},
		MemoryLockError: store.MemoryLockError,
	}, nil
}

// openCredentialGuest opens auth's credential guest with open (auth.Resolve
// or auth.OpenWithoutProfile) under the client's transport and memory-lock
// policy.
func openCredentialGuest(
	ctx context.Context,
	opts resolveOptions,
	open func(context.Context, ...auth.Option) (*auth.ProfileStore, error),
) (*auth.ProfileStore, error) {
	authOpts := []auth.Option{auth.WithRoundTripper(opts.Transport)}
	if opts.RequireLockedMemory {
		authOpts = append(authOpts, auth.RequireLockedMemory())
	}
	return open(ctx, authOpts...)
}

// credentialGuestError wraps a failure to open the credential guest.
func credentialGuestError(err error) error {
	if errors.Is(err, ErrMemoryLock) {
		// Under RequireLockedMemory the guest is refused before anything is
		// resolved — on a host that cannot lock or reserve its memory at all
		// (a 32-bit address space, a zero RLIMIT_MEMLOCK). Name which guest,
		// as the client's own report does.
		return fmt.Errorf("encrypt: credentials: the credential guest: %w", err)
	}
	return fmt.Errorf("encrypt: credentials: %w", err)
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
	strategy func(ctx context.Context, profile *auth.ProfileStore, noProfile error) (*auth.Strategy, error),
) (_ *resolvedCredentials, err error) {
	profile, err := openCredentialGuest(ctx, opts, auth.Resolve)
	// noProfile is why there is no profile to consult, when there is none:
	// kept for the errors that would have consulted it, so a profile that
	// exists but cannot be opened is not reported as "not logged in".
	var noProfile error
	if errors.Is(err, auth.ErrNoProfile) {
		// The strategies that need no profile still run, in a guest with
		// nothing mounted; every profile read on it is ErrNoProfile.
		noProfile = err
		profile, err = openCredentialGuest(ctx, opts, auth.OpenWithoutProfile)
	}
	if err != nil {
		return nil, credentialGuestError(err)
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
func clientKeyFromProfile(ctx context.Context, profile *auth.ProfileStore, noProfile error) (string, *ClientKey, error) {
	notConfigured := func(err error) error {
		return fmt.Errorf("%w: no client key: set %s and %s, or run `stash auth login`: %w",
			ErrNoCredentials, envClientID, envClientKey, err)
	}
	workspace, err := profile.CurrentWorkspaceStore(ctx)
	if errors.Is(err, auth.ErrNoProfile) && noProfile != nil {
		err = noProfile
	}
	if errors.Is(err, auth.ErrNoProfile) || errors.Is(err, auth.ErrNoCurrentWorkspace) {
		return "", nil, notConfigured(err)
	}
	if err != nil {
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
