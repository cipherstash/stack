package stackencrypt

import "net/http"

// ClientOption configures [NewClient]. Each one sets one thing; a later
// option setting the same thing wins. NewClient with none is a working
// client, with its credentials from [AutoCredentials].
type ClientOption func(*clientOptions)

// clientOptions is what the options set. Every zero value is the default.
type clientOptions struct {
	credentials         Credentials
	zerokmsURL          string
	keysetCacheSize     int
	transport           http.RoundTripper
	guest               []byte
	requireLockedMemory bool
}

// WithCredentials supplies the client id, the client key and the stackauth
// strategy the token comes from. The default, and what nil means, is
// [AutoCredentials]: the environment, then the developer profile.
// [NewCredentials] takes the three explicitly, and [OIDCFederation] mints tokens from an identity provider's.
//
// The client key is consumed: NewClient marshals it into the config buffer,
// wipes the key, and wipes the buffer once the guest has the key, so after
// NewClient returns — whatever the outcome, a configuration it refused
// included — the key is empty and the bytes it was built from are zero. A
// key is for one client.
func WithCredentials(c Credentials) ClientOption {
	return func(o *clientOptions) { o.credentials = c }
}

// WithZeroKMSURL pins the ZeroKMS endpoint. Without it, CS_ZEROKMS_HOST (or
// the legacy CS_VITUR_HOST) pins it if set — a set value that is not an
// http(s) URL is an error — and otherwise the endpoint is resolved from the
// access token's services claim on first use. The variables are read
// whatever the credentials, as stack-kms reads them.
func WithZeroKMSURL(url string) ClientOption {
	return func(o *clientOptions) { o.zerokmsURL = url }
}

// WithKeysetCacheSize sets how many keysets beyond the default the guest
// keeps loaded. Zero means the crate default (1024); negative is refused.
func WithKeysetCacheSize(n int) ClientOption {
	return func(o *clientOptions) { o.keysetCacheSize = n }
}

// WithTransport performs the client's HTTP requests: to ZeroKMS, and, for
// [AutoCredentials] and [OIDCFederation], the authentication requests
// stackauth's credential guest makes to CTS: an access-key exchange, a
// device-session refresh, a federation exchange. A RoundTripper scoped to
// the ZeroKMS host alone (a pinned client certificate, an egress allowlist)
// refuses those; the failure then surfaces as the token strategy's. Nil means
// http.DefaultTransport, the default.
func WithTransport(rt http.RoundTripper) ClientOption {
	return func(o *clientOptions) { o.transport = rt }
}

// WithGuest overrides the embedded wasm module. Nil means the embedded one,
// the default.
func WithGuest(wasm []byte) ClientOption {
	return func(o *clientOptions) { o.guest = wasm }
}

// WithRequireLockedMemory makes NewClient fail with ErrMemoryLock when the
// guest's memory cannot be locked in RAM or, on Linux, excluded from core
// dumps, instead of continuing with memory that may be swapped or dumped
// and reporting so through Client.MemoryLocked. It holds for the life of
// the client: a later growth of the guest's memory that cannot be locked is
// refused too, and what the guest already holds stays locked. When the
// growth was for a buffer the host is staging, the call fails with
// ErrMemoryLock and the client goes on. When it was for the guest's own
// allocation, the guest cannot report it: it aborts, and the client is
// closed with its keys wiped, the call still failing with ErrMemoryLock.
// Set it where swap is a real exposure and the deployment grants a lock
// limit with room for the guest to grow (RLIMIT_MEMLOCK on Linux; the error
// names the size held so far); see [Client.MemoryLocked].
//
// It covers the credential guest too, where the token strategy lives and
// the client key may have passed through. [AutoCredentials] and
// [OIDCFederation] open that guest under the same policy, so it is refused
// at NewClient and on every later growth alike. [NewCredentials]' guest is
// the stackauth store the caller opened: NewClient fails with
// ErrMemoryLock if that store's memory is unlocked when it is asked, but
// only the store's own policy governs its later growth, so open it with
// stackauth.RequireLockedMemory to hold it locked for the life of the
// client. Client.MemoryLocked reports the store's state live either way.
func WithRequireLockedMemory() ClientOption {
	return func(o *clientOptions) { o.requireLockedMemory = true }
}
