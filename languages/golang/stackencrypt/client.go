package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Config configures a [Client].
type Config struct {
	// ClientID is the ZeroKMS client id (a UUID string). Required.
	ClientID string
	// ClientKey is the v1 client key material: hex (the CS_CLIENT_KEY form,
	// either case) or standard padded base64 (the secretkey.json form).
	// Required. It enters guest memory once and is wiped from the config
	// buffer before any request is made; the Go-side copy this package
	// makes is wiped too. The caller's own string is the caller's.
	ClientKey string
	// Keyset pins the client's default keyset: a KeysetName or KeysetID.
	// Nil, or DefaultKeyset, means the ZeroKMS client's own default.
	Keyset KeysetSelector
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
}

// Client is one wasm instance holding one ZeroKMS client: its key, its
// default keyset, and the keysets it has loaded since. It is safe for
// concurrent use; calls are serialised internally, because a wasm instance
// is single-threaded. Close it to wipe its key material.
type Client struct {
	mu        sync.Mutex
	inst      *instance
	transport *transport
	closed    bool
	def       KeysetID
}

// NewClient instantiates the guest, loads the client key into it, and loads
// the default keyset — one ZeroKMS round trip. The returned client is ready
// to seal.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
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

	t := &transport{rt: rt, token: cfg.Token}
	inst, err := newInstance(ctx, wasm, t)
	if err != nil {
		return nil, err
	}
	c := &Client{inst: inst, transport: t}
	out, err := inst.call(ctx, inst.cipherInit, buf(encoded))
	if err != nil {
		_ = c.Close(ctx)
		return nil, fmt.Errorf("stackencrypt: cipher init: %w", err)
	}
	if len(out) != len(KeysetID{}) {
		_ = c.Close(ctx)
		return nil, fmt.Errorf("%w: cipher init returned %d bytes for the keyset id", ErrInternal, len(out))
	}
	copy(c.def[:], out)
	return c, nil
}

// encodeConfig renders the se_cipher_init object. The result holds the
// client key; the caller wipes it.
func encodeConfig(cfg Config) ([]byte, error) {
	if cfg.ClientID == "" || cfg.ClientKey == "" {
		return nil, errors.New("stackencrypt: Config.ClientID and Config.ClientKey are required")
	}
	fields := vcvalue.Object{
		{Key: "client_id", Value: cfg.ClientID},
		{Key: "client_key", Value: cfg.ClientKey},
	}
	switch k := cfg.Keyset.(type) {
	case nil, defaultKeyset:
	case KeysetName:
		fields = append(fields, vcvalue.Field{Key: "keyset", Value: string(k)})
	case KeysetID:
		fields = append(fields, vcvalue.Field{Key: "keyset_id", Value: k.String()})
	default:
		return nil, fmt.Errorf("stackencrypt: Config.Keyset must be a KeysetName or KeysetID, not %T", cfg.Keyset)
	}
	if cfg.ZeroKMSURL != "" {
		fields = append(fields, vcvalue.Field{Key: "zerokms_url", Value: cfg.ZeroKMSURL})
	}
	if cfg.KeysetCacheSize < 0 {
		return nil, errors.New("stackencrypt: Config.KeysetCacheSize must not be negative")
	}
	if cfg.KeysetCacheSize > 0 {
		fields = append(fields, vcvalue.Field{Key: "keyset_cache_size", Value: strconv.Itoa(cfg.KeysetCacheSize)})
	}
	return vcffi.Marshal(fields)
}

// Close shuts the guest down — the client key and every loaded index key
// are wiped inside the instance — and releases the runtime. Idempotent.
// Every call after it fails with ErrState.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// A trapped or already-closed module cannot run se_shutdown; the runtime
	// close still frees its memory. Nothing else can be done host-side.
	_, _ = c.inst.shutdown.Call(ctx)
	return c.inst.close(ctx)
}

// DefaultKeysetID is the id of the client's default keyset, resolved at
// NewClient.
func (c *Client) DefaultKeysetID() KeysetID { return c.def }

// Keyset resolves a selector to its keyset id: the first use of a name or
// id on this client is one ZeroKMS round trip, later uses come from the
// guest's cache. Use it at boot to validate a tenant's keyset and learn its
// id. DefaultKeyset never makes a request.
func (c *Client) Keyset(ctx context.Context, sel KeysetSelector) (KeysetID, error) {
	if sel == nil {
		return KeysetID{}, errNilSelector
	}
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

// Cipher binds the client to one keyset. No request is made here: the
// keyset is resolved by the guest on the cipher's first use (and cached),
// so a Cipher is cheap to make per call, per tenant or per request.
func (c *Client) Cipher(sel KeysetSelector) *Cipher {
	if sel == nil {
		sel = DefaultKeyset
	}
	return &Cipher{client: c, keyset: sel}
}

// DefaultCipher is Cipher(DefaultKeyset).
func (c *Client) DefaultCipher() *Cipher { return c.Cipher(DefaultKeyset) }

// Decrypt opens a ciphertext produced by any keyset of this client: each
// leaf is opened under the keyset it was sealed with, with one batched key
// retrieval per keyset. ct is the shape Cipher.Encrypt returns; aad must be
// what the value was sealed under.
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
func (c *Client) call(ctx context.Context, f func(*instance) ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrState
	}
	return f(c.inst)
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
