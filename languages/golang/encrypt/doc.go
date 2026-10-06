// Package encrypt is the Stack Encrypt Go SDK: searchable, field-level
// encryption under per-value ZeroKMS data keys, running the stack-encrypt
// Rust engine unmodified inside a WASI guest under wazero (CGO_ENABLED=0).
//
// # Use the SDK
//
// 1. Add the generator to your module (Go 1.24 or later):
//
//	go get -tool github.com/cipherstash/stack/languages/golang/cmd/stashgen
//
// 2. Put a stash tag on every exported field of the struct, and a go:generate
// comment beside it:
//
//	//go:generate go tool stashgen -type User
//	type User struct {
//		_     struct{} `stash:"context=users"`
//		ID    int64    `stash:"id,passthrough"`
//		Email string   `stash:"email,encrypt,index=equality;match"`
//		Age   uint32   `stash:"age,encrypt,index=equality;ore"`
//	}
//
// 3. Run the generator. It writes user_stash.go beside the struct:
//
//	go generate ./...
//
// 4. Commit the generated file.
//
// 5. Call the generated functions where you write and read:
//
//	client, err := encrypt.NewClient(ctx)
//	cipher := client.Keyset(encrypt.KeysetName("tenant-42"))
//	encrypted, err := users.Encrypt(ctx, cipher, people)   // []users.EncryptedUser, one request
//	people, err := users.Decrypt(ctx, cipher, encrypted)   // []users.User
//	term, err := users.Fields.Email.Equality(ctx, cipher, "bob@example.com")
//
// 6. Store the encrypted type. Each field is one or more columns of bytes
// ([Ciphertext] and the term types), so database/sql, pgx, sqlx and GORM take
// it as it is.
//
// 7. Run the generator again after each change to the struct or to a tag. A
// change to the fields of the struct stops the build until you do.
//
// 8. In CI, run the generator and fail when a generated file changes:
//
//	go generate ./... && git diff --exit-code
//
// The rest is the reference. The generator's own reference — the tag
// grammar, the flags, what it writes and what it refuses — is in
// cmd/stashgen/README.md.
//
// # Shape
//
// A [Client] is one wasm instance and one ZeroKMS client: [NewClient]
// resolves the client's [Credentials], instantiates the embedded guest, hands
// it the client key once — the [ClientKey] the credentials resolved to is
// consumed and wiped, whatever the outcome — and loads the client's default
// keyset. It takes functional options ([ClientOption]), every one with a
// default, so NewClient(ctx) alone is a working client. [Client.Close] runs
// the guest's shutdown so the client key and every loaded index key are
// wiped before the instance is freed.
//
// A [Cipher] is the client bound to one keyset ([Client.Keyset] and
// [Client.DefaultKeyset]) and to any extension of the context
// ([Cipher.Extend]): what changes from one caller to the next — a tenant, a
// region — attaches here and not to each call, so the write, the query and
// the read cannot use different ones. A Cipher opens only its own keyset's
// records; the [Client] opens records from any of its keysets. Both are a
// [Decrypter], which the generated Decrypt functions take.
//
// # Declarations
//
// A struct's stash tags declare how each field is encrypted: the context of
// the struct, and for each field whether it is sealed, which indexes are
// derived beside it, or whether it passes through as it is. stashgen reads
// the tags and writes the encrypted type, Encrypt, Decrypt and Fields into
// the struct's package; the generated code hands the declaration to the
// engine as data through package gensupport, and the engine runs the same
// plan the Rust chain and the derive run. A program never builds or names a
// plan, and no call takes a context or an index choice of its own.
//
// Passthrough fields never cross the binding: the engine does nothing to a
// passthrough value that a program could observe, and the FFI codec cannot
// carry every Go type a program stores beside a ciphertext (a time.Time, a
// driver.Valuer). An opaque struct crosses as one JSON document and is one
// column.
//
// # Terms
//
// A sealed field with an index gets a term beside its ciphertext:
// [EqualityTerm], [MatchTerm], [OreTerm] or [OpeTerm], byte-equal to the ones
// the Rust crate derives, so a term from a generated Fields entry compares
// against a stored term from any language. The indexes are [Equality],
// [Match], [Ore] and [Ope]; [JSON] is declared and refused until the engine
// derives it. Every stored type implements driver.Valuer and sql.Scanner.
//
// # Transport and auth
//
// The guest imports exactly two host functions: an HTTP send, served by any
// [net/http.RoundTripper], and a bearer-token fetch, served by the
// credentials' auth strategy. What crosses per ZeroKMS call is what would
// cross TLS anyway; derived key material never leaves the guest. Under
// [AutoCredentials] and [OIDCFederation] the same RoundTripper also carries
// the authentication requests to CTS, so one scoped to the ZeroKMS host alone
// is not enough. Under [NewCredentials] those requests go through the store
// the caller opened the strategy from.
//
// # Credentials
//
// A [Credentials] supplies the client id, the client key and the auth
// strategy the token comes from, and NewClient resolves it host-side: the
// crypto guest is never given the environment or a filesystem to find them
// in. The default, [AutoCredentials], mirrors the Rust client — the
// environment first (CS_CLIENT_ACCESS_KEY with CS_WORKSPACE_CRN for the
// token, CS_CLIENT_ID with CS_CLIENT_KEY for the key), then the developer
// profile, which it reads through the auth package's credential guest.
// CS_ZEROKMS_HOST (or CS_VITUR_HOST) pins the endpoint whatever the
// credentials. [NewCredentials] takes a client id, a client key and a
// strategy explicitly, and [OIDCFederation] mints the token from an identity
// provider's. None takes a raw token: a token is always a strategy's, since
// a raw one cannot be refreshed when it expires. Credentials that cannot be
// resolved fail NewClient with [ErrNoCredentials]; credentials that resolve
// but do not work fail it too, at the one ZeroKMS round trip it makes.
//
// # Errors
//
// The generator and the compiler find a mistake in a declaration, so no call
// returns an error for one. A call returns an error for a key, for the
// network, or for stored data: [ErrForeignKeyset] when a *Cipher is given a
// record another keyset sealed, [ErrAuthentication] or [ErrForbidden] for a
// ciphertext that does not open under its field's context, [ErrEncoding] for
// a stored value that does not fit its declaration. Read them with errors.Is.
// No error, warning or log line holds a plaintext value; a generated type
// hides its sealed fields when a program prints it.
//
// # Host runtime
//
// The guest also imports WASI random_get and clock_time_get, and the
// cipher's security rests on the first: ZeroKMS IVs and AEAD nonces are
// drawn from it. wazero's defaults for both are deterministic, so every
// instance is configured with the process CSPRNG ([crypto/rand.Reader]) and
// the system clocks.
//
// # Memory
//
// Every key the guest holds — the client key, each loaded index key, each
// data key for the length of a call — lives in the guest's linear memory,
// and the package supplies that memory itself: reserved once so growth never
// copies it, locked in RAM (mlock, VirtualLock) so it is never written to
// swap, excluded from core dumps on Linux (MADV_DONTDUMP), and wiped before
// it is released, on every release path. That is done at allocation, where
// the caller cannot get it wrong, and not at exit, where they cannot be
// relied on.
//
// The lock is best effort: RLIMIT_MEMLOCK defaults to 64 KiB on many Linux
// hosts and the guest is larger, so it is commonly refused, and a client
// then works on with memory that may be swapped. [Client.MemoryLocked]
// reports the outcome and [Client.MemoryLockError] the reason, naming the
// limit to raise. [WithRequireLockedMemory] turns a refusal into a
// [NewClient] failure with [ErrMemoryLock], and refuses any later growth of
// the guest's memory that cannot be locked. A Client prints its memory state
// ([Client.String]) and logs it ([Client.LogValue]).
//
// Between calls the guest holds the client key and its keyset cache and
// nothing else: data keys are per-call values wiped when the export returns,
// and every buffer staged for a call is wiped before the call's result is
// returned.
package encrypt
