// Package stackencrypt is the Go binding of stack-encrypt: ZeroKMS-backed
// field-level encryption with searchable index terms, running the Rust
// crate unmodified inside a WASI guest under wazero (CGO_ENABLED=0).
//
// # Shape
//
// A [Client] is one wasm instance and one ZeroKMS client: [NewClient]
// resolves the client's [Credentials], instantiates the embedded guest,
// hands it the client key once — the [ClientKey] the credentials resolved
// to is consumed and wiped, whatever the outcome — and loads the client's
// default keyset. It takes functional options ([ClientOption]), every one
// with a default, so NewClient(ctx) alone is a working client. Every keyset
// the client uses after that is selected per call through a
// [KeysetSelector] and loaded on first use by the guest's own bounded
// cache; nothing the host could allocate, alias or free crosses the
// boundary. [Client.Close] runs the guest's shutdown so the client key and
// every loaded index key are wiped before the instance is freed — closing a
// wasm instance runs no Rust destructors on its own. Close is hygiene, not
// the security story: see Memory below.
//
// A [Cipher] is the client bound to one keyset ([Client.Keyset] and
// [Client.DefaultKeyset], the Rust crate's StackCipher::keyset and
// default_keyset): it seals values, derives terms and encrypts records
// under that keyset, and opens only that keyset's ciphertexts. The
// [Client] itself opens ciphertexts from any keyset ([Client.Decrypt] and
// friends), fetching batched key retrievals per keyset the leaves were
// sealed under.
//
// # Values
//
// Values cross the boundary in vitaminc's FFI codec ([vcffi]) and are
// modelled as Go natives ([vcvalue]): builtins, slices, maps and structs
// seal by reflection, [vcvalue.Plain] marks a passthrough field, and a
// type implementing [vcffi.Encryptable] drives its own encoding. A
// ciphertext is the same dynamic shape with [Sealed] leaves — a distinct
// type from vcvalue's, because a stack-encrypt leaf is not a vitaminc leaf
// and must never scan or marshal where one belongs. The leaf bytes are the
// frozen stack-encrypt storage format; the transport encoding is not.
//
// # Records and terms
//
// [Cipher.EncryptRecords] is the runtime form of the Rust derive: a struct's
// `stash` tags say, per field, which context to bind and which index terms
// to produce, and one call seals every row of a slice from batched key
// requests. The same plan is a value ([Plan]): [PlanFromTags] is what the
// tags parse to, [NewPlan] builds one for a struct that cannot carry tags
// (generated code), and [WithPlan] runs a record call under it. Key
// requests are batched 500 keys at a time, in both directions: one request
// for any ordinary value or batch, one more per 500 sealed leaves beyond
// that. Terms ([EqualityTerm], [MatchTerm], [OreTerm], [OpeTerm]) are
// byte-equal to the ones the Rust crate derives, so a probe from
// [Cipher.Term] compares against a stored term from any language.
// [Cipher.Term] takes a context and returns an error from day one: term
// derivation may be a ZeroKMS round trip.
//
// # Transport and auth
//
// The guest imports exactly two host functions: an HTTP send, served by any
// [net/http.RoundTripper], and a bearer-token fetch, served by the
// credentials' stackauth strategy. What crosses per ZeroKMS call is what would cross TLS
// anyway; derived key material never leaves the guest. Under
// [AutoCredentials] the same RoundTripper also carries the authentication
// requests to CTS, so one scoped to the ZeroKMS host alone is not enough.
//
// # Credentials
//
// A [Credentials] supplies the client id, the client key and the stackauth
// strategy the token comes from, and NewClient resolves it host-side: the crypto guest is never
// given the environment or a filesystem to find them in. The default,
// [AutoCredentials], mirrors the Rust client — the environment first
// (CS_CLIENT_ACCESS_KEY with CS_WORKSPACE_CRN for the token, CS_CLIENT_ID
// with CS_CLIENT_KEY for the key), then the developer profile, which it
// reads through stackauth's credential guest, where the token strategies
// also run. CS_ZEROKMS_HOST (or CS_VITUR_HOST) pins the endpoint whatever
// the credentials. [NewCredentials] takes a client id, a client key and a
// strategy explicitly, and [OIDCFederation] mints the token from an
// identity provider's. Pass one with [WithCredentials]. Those three are
// the only kinds of Credentials, and none takes a raw token: a token is
// always a stackauth strategy's, since a raw one cannot be refreshed when
// it expires and would bypass the cross-process lock a device-session
// refresh holds with the CLI.
// Credentials that cannot be resolved fail NewClient with
// [ErrNoCredentials]; credentials that resolve but do not work fail it too,
// at the one ZeroKMS round trip it makes.
//
// # Host runtime
//
// The guest also imports WASI random_get and clock_time_get, and the
// cipher's security rests on the first: ZeroKMS IVs and AEAD nonces are
// drawn from it. wazero's defaults for both are deterministic, so every
// instance is configured with the process CSPRNG ([crypto/rand.Reader])
// and the system clocks. An embedder that instantiates the guest module
// under its own wazero configuration must do the same.
//
// # Memory
//
// Every key the guest holds — the client key, each loaded index key, each
// data key for the length of a call — lives in the guest's linear memory,
// and the package supplies that memory itself rather than taking wazero's
// default Go slice. It is reserved once at the module's declared maximum,
// so growth never copies it (wazero's default grows with append, which
// would leave an unwiped copy of every key to the garbage collector);
// locked in RAM (mlock, VirtualLock) so it is never written to swap;
// excluded from core dumps on Linux (MADV_DONTDUMP); and wiped before it
// is released, on every release path.
//
// That is deliberately done at allocation, where the caller cannot get it
// wrong, and not at exit, where they cannot be relied on: no deferred
// [Client.Close] runs on SIGTERM without a handler, SIGKILL, the OOM
// killer, a panic on another goroutine or os.Exit, and the package installs
// no signal handler — that is the application's to own, and covers only
// the first of those anyway. The kernel zeroes a dead process's pages
// before anyone else sees them; the lock and the dump exclusion close the
// two places a copy could otherwise outlive the process.
//
// The lock is best effort: RLIMIT_MEMLOCK defaults to 64 KiB on many
// Linux hosts and the guest is larger, so it is commonly refused, and a
// client then works on with memory that may be swapped — which is all
// that is lost, and nothing on a host without swap. [Client.MemoryLocked]
// reports the outcome and [Client.MemoryLockError] the reason, naming the
// limit to raise (ulimit -l, a systemd LimitMEMLOCK=, a pod's
// securityContext). [WithRequireLockedMemory] turns a refusal into a
// [NewClient] failure with [ErrMemoryLock], for deployments that would
// rather not start than run unlocked; it also refuses any later growth of
// the guest's memory that cannot be locked, so the limit granted must
// leave the guest room to grow: a refused growth fails the call with
// [ErrMemoryLock], and closes the client when the growth was the guest's
// own allocation rather than a host-staged buffer. The report and the
// policy cover the credential guest as well; with [NewCredentials] that is
// the caller's stackauth store, which NewClient refuses under the policy
// when it is unlocked, and which should be opened with
// stackauth.RequireLockedMemory to stay locked (see
// [WithRequireLockedMemory]). A Client prints its memory state
// ([Client.String]) and logs it ([Client.LogValue]). An embedder running
// the guest under its own wazero configuration gets none of this unless
// it supplies an allocator of its own.
//
// Between calls the guest holds the client key and its keyset cache (each
// keyset's index key) and nothing else: data keys are per-call values in
// the guest's Rust code, wiped by their ZeroizeOnDrop when the export
// returns, and every buffer staged for a call is wiped by se_dealloc
// before the call's result is returned. The residency tests pin the
// second; the first is the Rust crate's own guarantee.
package stackencrypt
