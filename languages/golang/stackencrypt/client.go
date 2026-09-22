package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"sync"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Config configures a [Client].
type Config struct {
	// ClientID is the ZeroKMS client id (a UUID string). Required.
	ClientID string
	// ClientKey is the v1 client key material: hex (the CS_CLIENT_KEY form,
	// either case) or standard padded base64 (the secretkey.json form),
	// wrapped by [NewClientKey] or read from the developer profile by
	// stackauth. Required. It is consumed: NewClient marshals it into the
	// config buffer, wipes the key, and wipes the buffer once the guest has
	// the key, so after NewClient returns — whatever the outcome, a config
	// it refused included — the ClientKey is empty and the bytes it was
	// built from are zero. A key is for one client.
	ClientKey *ClientKey
	// ZeroKMSURL pins the ZeroKMS endpoint. When empty the endpoint is
	// resolved from the access token's services claim on first use.
	ZeroKMSURL string
	// KeysetCacheSize is how many keysets beyond the default the guest keeps
	// loaded; zero means the crate default (1024).
	KeysetCacheSize int
	// Transport performs the HTTP requests to ZeroKMS. Nil means
	// http.DefaultTransport.
	Transport http.RoundTripper
	// Token supplies the bearer token for every request. Required.
	Token TokenSource
	// Guest overrides the embedded wasm module. Nil means the embedded one.
	Guest []byte
	// RequireLockedMemory makes NewClient fail with ErrMemoryLock when the
	// guest's memory cannot be locked in RAM or, on Linux, excluded from
	// core dumps, instead of continuing with memory that may be swapped or
	// dumped and reporting so through Client.MemoryLocked. It holds for
	// the life of the client: a later growth of the guest's memory that
	// cannot be locked is refused too, and what the guest already holds
	// stays locked. When the growth was for a buffer the host is staging,
	// the call fails with ErrMemoryLock and the client goes on. When it
	// was for the guest's own allocation, the guest cannot report it: it
	// aborts, and the client is closed with its keys wiped, the call still
	// failing with ErrMemoryLock. Set it where swap is a real exposure and
	// the deployment grants a lock limit with room for the guest to grow
	// (RLIMIT_MEMLOCK on Linux; the error names the size held so far); see
	// [Client.MemoryLocked].
	RequireLockedMemory bool
}

// Client is one wasm instance holding one ZeroKMS client: its key, its
// default keyset, and the keysets it has loaded since. It is safe for
// concurrent use; calls are serialised internally, because a wasm instance
// is single-threaded. Close it when done, as with any resource.
//
// Its key material lives in the guest's linear memory, which this package
// supplies: reserved once so it never moves, locked in RAM and excluded
// from core dumps where the platform allows, and wiped before it is
// released. None of that depends on Close running — no exit path a process
// can take (a signal with no handler, SIGKILL, the OOM killer, a panic on
// another goroutine, os.Exit) runs deferred calls, and none of them is
// where the protection lives. [Client.MemoryLocked] reports whether the
// lock was granted.
type Client struct {
	mu        sync.Mutex
	inst      *instance
	transport *transport
	// closed refuses further calls: either Close ran, or an interrupted
	// call took the module down under us (see Client.call). released is
	// the runtime's own state, tracked apart from it because those two
	// things come apart: an interrupted call closes the module — and so
	// the client — while the runtime and the host modules beside it are
	// still allocated. Close is what frees those, so it must do its work
	// even on a client that is already closed.
	closed   bool
	released bool
	def      KeysetID
	// cleanup releases the instance if the Client becomes unreachable
	// without Close: the forgot-to-close case in a running process. It
	// does nothing at process exit, and is not meant to.
	cleanup runtime.Cleanup
}

// NewClient instantiates the guest, loads the client key into it, and loads
// the default keyset — one ZeroKMS round trip. The returned client is ready
// to seal.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	// The key is consumed whatever happens below: a config refused before
	// the key is marshalled must not hand it back live. Nil-safe, and a
	// no-op after the wipe on the accepted path.
	defer cfg.ClientKey.Wipe()
	if cfg.Token == nil {
		return nil, errors.New("stackencrypt: Config.Token is required")
	}
	wasm := cfg.Guest
	if wasm == nil {
		var err error
		if wasm, err = embeddedGuest(); err != nil {
			return nil, err
		}
	}
	rt := cfg.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	encoded, err := encodeConfig(cfg)
	if err != nil {
		return nil, err
	}
	defer wipe(encoded)
	// The key is consumed: it is in the config buffer now, and the buffer
	// is wiped once the guest has it. Wiping the key here rather than after
	// the init call keeps the exposure to one copy from this point on,
	// whatever the init's outcome.
	cfg.ClientKey.Wipe()

	t := &transport{rt: rt, token: cfg.Token}
	inst, err := newInstance(ctx, wasm, t, guest.PolicyFor(cfg.RequireLockedMemory))
	if err != nil {
		return nil, err
	}
	c := newClient(inst, t)
	out, err := c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.cipherInit, buf(encoded))
	})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("stackencrypt: cipher init: %w", err)
	}
	if len(out) != len(KeysetID{}) {
		_ = c.Close()
		return nil, fmt.Errorf("%w: cipher init returned %d bytes for the keyset id", ErrInternal, len(out))
	}
	copy(c.def[:], out)
	return c, nil
}

// newClient wraps an instance and arms its cleanup. The cleanup takes the
// instance, not the client: a cleanup whose argument reaches its object
// keeps that object alive forever.
func newClient(inst *instance, t *transport) *Client {
	c := &Client{inst: inst, transport: t}
	c.cleanup = runtime.AddCleanup(c, func(inst *instance) { _ = inst.release() }, inst)
	return c
}

// MemoryLocked reports whether the guest's memory — where the client key
// and every loaded index key live — is locked in RAM and, on Linux,
// excluded from core dumps. False means the lock was refused (on Linux,
// most often RLIMIT_MEMLOCK, which defaults to 64 KiB on many hosts) or is
// not available on this platform, and the client is working on with
// memory the kernel may swap out. Nothing else changes. A production
// checklist should assert this, or set [Config.RequireLockedMemory] and
// let NewClient refuse. [Client.MemoryLockError] says why.
func (c *Client) MemoryLocked() bool { return c.inst.mem.LockError() == nil }

// MemoryLockError is why MemoryLocked is false: an error wrapping
// ErrMemoryLock that names what was refused and the limit that refused it.
// Nil while the memory is locked.
func (c *Client) MemoryLockError() error {
	if err := c.inst.mem.LockError(); err != nil {
		return guest.MemoryLockError(err)
	}
	return nil
}

// String implements fmt.Stringer so that a Client printed with %v or %s
// shows its memory state: "locked", or the refusal. Nothing secret is
// printed. The state is what an operator reading a startup log needs to
// see, and [Client.LogValue] gives it structured form.
func (c *Client) String() string {
	return fmt.Sprintf("stackencrypt.Client{memory: %s}", c.inst.mem)
}

// LogValue implements slog.LogValuer: a group with memory_locked and, when
// false, memory_lock_error.
func (c *Client) LogValue() slog.Value { return c.inst.mem.LogValue() }

// encodeConfig renders the se_cipher_init object. The result holds the
// client key; the caller wipes it, and the key it was read from.
func encodeConfig(cfg Config) ([]byte, error) {
	if cfg.ClientID == "" || cfg.ClientKey.IsZero() {
		return nil, errors.New("stackencrypt: Config.ClientID and Config.ClientKey are required")
	}
	// Every refusal comes before the key is copied, so a rejected config
	// leaves nothing but the key itself, which the caller wipes.
	if cfg.KeysetCacheSize < 0 {
		return nil, errors.New("stackencrypt: Config.KeysetCacheSize must not be negative")
	}
	// The key crosses as text: the guest's config parser takes the hex or
	// base64 form as the CS_CLIENT_KEY variable and secretkey.json hold it.
	// The string is a copy the marshaller reads once — and copies once more
	// into its own scratch before appending — and the encoded buffer that
	// results is what the caller wipes. A string cannot be wiped, and
	// neither can the marshaller's copy; both live until the collector takes
	// them: the copies of the key this package cannot zero, accepted for the
	// length of NewClient. A marshaller that took bytes would remove both.
	fields := vcvalue.Object{
		{Key: "client_id", Value: cfg.ClientID},
		{Key: "client_key", Value: string(guest.KeyBytes(cfg.ClientKey))},
	}
	if cfg.ZeroKMSURL != "" {
		fields = append(fields, vcvalue.Field{Key: "zerokms_url", Value: cfg.ZeroKMSURL})
	}
	if cfg.KeysetCacheSize > 0 {
		fields = append(fields, vcvalue.Field{Key: "keyset_cache_size", Value: strconv.Itoa(cfg.KeysetCacheSize)})
	}
	return vcffi.Marshal(fields)
}

// Close shuts the guest down — the client key and every loaded index key
// are wiped inside the instance — and releases the runtime and the
// guest's memory, which is wiped on the way out. Idempotent. Every call
// after it fails with ErrState.
//
// It takes no context because it does no I/O and must not be skippable:
// a deferred Close is ordinary resource hygiene, and the memory's
// protection (see [Client]) does not wait on it.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Idempotency turns on the runtime, not on the client: a client an
	// interrupted call already closed has never released its runtime.
	if c.released {
		return nil
	}
	c.released = true
	c.closed = true
	c.cleanup.Stop()
	return c.inst.release()
}

// Keyset binds the client to one keyset, by name or by id: Rust's
// StackCipher::keyset. No request is made here — Go has no await, so the
// keyset is resolved by the guest on the cipher's first use (and cached),
// which makes a Cipher cheap to make per call, per tenant or per request.
// [Cipher.KeysetID] is the explicit resolution point. A nil selector is a
// programming error and panics; the default keyset is [Client.DefaultKeyset].
func (c *Client) Keyset(sel KeysetSelector) *Cipher {
	if sel == nil {
		panic("stackencrypt: Client.Keyset(nil); the default keyset is Client.DefaultKeyset")
	}
	return &Cipher{client: c, keyset: sel}
}

// DefaultKeyset binds the client to its default keyset — the one a ZeroKMS
// administrator set for this client, which is what naming no keyset
// resolves to: Rust's StackCipher::default_keyset. Loaded at NewClient, so
// using it never touches ZeroKMS. There is no way to redefine it from here;
// which keyset is the default is the server's to say. Any other keyset is
// [Client.Keyset].
func (c *Client) DefaultKeyset() *Cipher { return &Cipher{client: c, keyset: defaultKeyset{}} }

// resolveKeyset asks the guest for a selector's keyset id: the first use
// of a name or id on this client is one ZeroKMS round trip, later uses
// come from the guest's cache. The default keyset never makes a request.
func (c *Client) resolveKeyset(ctx context.Context, sel KeysetSelector) (KeysetID, error) {
	encoded, err := vcffi.Marshal(sel.selector())
	if err != nil {
		return KeysetID{}, err
	}
	out, err := c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.keyset, buf(encoded))
	})
	if err != nil {
		return KeysetID{}, err
	}
	var id KeysetID
	if len(out) != len(id) {
		return id, fmt.Errorf("%w: se_keyset returned %d bytes", ErrInternal, len(out))
	}
	copy(id[:], out)
	return id, nil
}

// Decrypt opens a ciphertext produced by any keyset of this client: each
// leaf is opened under the keyset it was sealed with, with batched key
// retrievals per keyset (one per 500 leaves sealed under it). ct is the
// shape Cipher.Encrypt returns; aad must be what the value was sealed
// under.
func (c *Client) Decrypt(ctx context.Context, ct any, aad []byte) (any, error) {
	return c.decryptValue(ctx, anyKeyset{}, ct, aad, false)
}

// DecryptElement is Decrypt for a value sealed as a sequence element; see
// Cipher.DecryptElement.
func (c *Client) DecryptElement(ctx context.Context, ct any, aad []byte) (any, error) {
	return c.decryptValue(ctx, anyKeyset{}, ct, aad, true)
}

// DecryptRecords opens records produced by Cipher.EncryptRecords under any
// keyset of this client, into a slice; see Cipher.DecryptRecords.
func (c *Client) DecryptRecords(ctx context.Context, records []EncryptedRecord, out any, opts ...RecordOption) error {
	return c.decryptRecords(ctx, anyKeyset{}, records, out, opts)
}

// DecryptRecord opens one record under any keyset of this client; see
// Cipher.DecryptRecord.
func (c *Client) DecryptRecord(ctx context.Context, record EncryptedRecord, out any, opts ...RecordOption) error {
	return c.decryptRecord(ctx, anyKeyset{}, record, out, opts)
}

// call runs f on the instance under the client's lock.
//
// A call interrupted by its context (the runtime closes the module on a
// deadline or cancellation, see newInstance) leaves the instance closed:
// its key material is gone with its memory and no further call can run.
// The client is then closed, so later calls are ErrState rather than a
// runtime error, and Close releases the runtime without a shutdown call.
// A guest that trapped is closed the same way, by this method: the guest
// builds with panic-as-abort, so a trap is an abort mid-export, after
// which its state is unknown and its keys are better wiped than reused.
func (c *Client) call(ctx context.Context, f func(*instance) ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.inst.module.IsClosed() {
		c.closed = true
		return nil, ErrState
	}
	growth := c.inst.mem.GrowthRefusal()
	out, err := f(c.inst)
	switch {
	case c.inst.module.IsClosed():
		c.closed = true
		if err == nil {
			err = ErrState
		}
		err = fmt.Errorf("%w: interrupted call closed the client", err)
	case errors.Is(err, errGuestTrap):
		// No guest code is running (f has returned), so the close is
		// immediate: the module's memory is wiped and freed here.
		c.closed = true
		_ = c.inst.module.Close(context.Background())
		err = fmt.Errorf("%w; the client is closed", err)
	}
	// Under RequireLockedMemory a growth that cannot be locked is refused,
	// and the guest sees only a failed allocation — or, for an allocation
	// of its own, aborts, and the trap closed the client above. Name the
	// real cause either way. The refusal is this call's, not the client's:
	// the range went back unused, so MemoryLocked still holds.
	if g := c.inst.mem.GrowthRefusal(); err != nil && g.Refused != growth.Refused {
		err = fmt.Errorf("%w (growth refused under RequireLockedMemory): %w", guest.MemoryLockError(g.Reason), err)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) decryptValue(ctx context.Context, sel KeysetSelector, ct any, aad []byte, element bool) (any, error) {
	encoded, err := marshalCipherText(ct)
	if err != nil {
		return nil, err
	}
	opts, err := vcffi.Marshal(options(sel))
	if err != nil {
		return nil, err
	}
	out, err := c.call(ctx, func(inst *instance) ([]byte, error) {
		fn := inst.decrypt
		if element {
			fn = inst.decryptElement
		}
		return inst.call(ctx, fn, buf(encoded), buf(aad), buf(opts))
	})
	if err != nil {
		return nil, err
	}
	// The output is plaintext: decode, then wipe the transport copy.
	defer wipe(out)
	return vcffi.Unmarshal(out)
}
