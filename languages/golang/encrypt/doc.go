// Package encrypt is the Stack Encrypt Go SDK: searchable, field-level
// encryption under per-value ZeroKMS data keys, running the stack-encrypt
// Rust engine unmodified inside a WASI guest under wazero (CGO_ENABLED=0).
//
// # Use the SDK
//
// 1. Add the generator to your module (Go 1.26.10 or later, or 1.27.3 or later
// on 1.27: the first releases whose crypto/x509 blocks the compromised eMudhra
// intermediate CAs, CVE-2026-111943):
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
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	cipher := client.Keyset(encrypt.KeysetName("tenant-42"))
//	encrypted, err := users.Encrypt(ctx, cipher, people) // []users.EncryptedUser
//	opened, err := users.Decrypt(ctx, cipher, encrypted) // []users.User
//	term, err := users.Fields.Email.Equality(ctx, cipher, "bob@example.com")
//
// Encrypt and Decrypt send one ZeroKMS request for each 500 sealed values in
// the batch, plus one the first time a keyset is used.
//
// 6. Store the encrypted type. Each sealed field is one or more columns of
// bytes ([Ciphertext] and the term types), each implementing driver.Valuer
// and sql.Scanner, so a database library binds and scans each one as bytes;
// map each one to its own column.
//
// 7. Run the generator again after each change to the struct or to a tag. A
// change to the fields of the struct stops the build until you do.
//
// 8. In CI, run the generator and fail when a generated file changes:
//
//	go generate ./... && git diff --exit-code && test -z "$(git status --porcelain)"
//
// git diff sees only tracked files; the git status check also fails on a
// generated file that was never committed.
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
// A match index needs text with at least one token: the engine derives no
// match term for an empty string, separator-only text, or text shorter than
// the n-gram length (3 characters), because an empty term would match every
// row. Encrypt then fails for the whole batch with [ErrTerm], naming the row,
// the field and the index, so an optional or short value does not belong
// under match.
//
// # Transport and auth
//
// The guest imports exactly three host functions: an HTTP send, served by
// any [net/http.RoundTripper], a bearer-token fetch, served by the
// credentials' auth strategy, and a key vendor credential fetch, served by
// the source given with [WithKeyVendor]. What crosses per ZeroKMS or vendor
// call is what would cross TLS anyway; derived and unwrapped key material
// never leaves the guest. Under
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
// # Key vendor backends
//
// A key vendor backend is an alternative to ZeroKMS: [AWSKMS],
// [GoogleCloudKMS], [AzureKeyVault], [VaultTransit] or [StaticKey]. Give it
// with [WithKeyVendor], and its keyset records (the "stack-keyset:…" texts)
// with [WithKeysetRecords]:
//
//	client, err := encrypt.NewClient(ctx,
//		encrypt.WithKeyVendor(encrypt.AWSKMS{Region: "us-east-1", Credentials: creds}),
//		encrypt.WithKeysetRecords(os.Getenv("USERS_KEYSET_RECORD")))
//
// With no [WithCredentials] the client has no ZeroKMS and needs no
// CipherStash credentials. Its default keyset is its only keyset record, or
// the one [WithDefaultKeyset] names, and a call that needs ZeroKMS fails
// with [ErrNoZeroKMS]. With WithCredentials too, the client holds both: a
// keyset in a record goes to the vendor, and every other keyset, the default
// included, goes to ZeroKMS. Select a vendor keyset by its record's name or
// id with [Client.Keyset]. A value sealed under one backend never opens
// under the other.
//
// The guest builds and signs every vendor request. The host supplies only
// short-lived credentials, per request: temporary AWS credentials, a Google
// OAuth access token, an Azure access token for the scope the guest names,
// or a Vault token. Fill them from the vendor's own Go credential chain
// through [AWSCredentialsFunc], [AccessTokenFunc] or [OAuth2AccessTokens].
// This package imports no vendor SDK.
//
// Each keyset record fixes one key mode. Wrapped data keys give each value
// its own vendor-wrapped data key. Derived data keys derive each data key
// from one root key per keyset (HKDF-SHA256). In wrapped data key mode, no
// key outlives the call that needed it. In derived data key mode, the root
// key is cached for the TTL. In both modes, the database holds no usable
// key material.
//
//	                    wrapped data keys            derived data keys
//	key lifetime        index key: one call;         root key: cached in the guest
//	                    data key: one call           for 5 minutes (WithRootKeyTTL);
//	                                                 the rest derived per call
//	vendor calls per    one per sealed or opened     0, or 1 per keyset when the
//	  call, per keyset  value (Vault: 1 per 250),    root key is not cached
//	                    plus 1 when the call
//	                    derives search terms
//	the vendor can      every value it seals or      the root key unwrap: a refusal
//	  refuse            opens, and every call that   takes effect when the cached
//	                    derives search terms         root key expires
//
// The guest sends vendor calls one at a time. Under wrapped data keys each
// separate call that derives a search term, such as a field's Equality,
// costs one vendor round trip for the index key: encrypt many rows in one
// Encrypt call, not one call per row. The first use of a Vault Transit key
// or an Azure key costs one more call, a key read.
//
// The associated data (the keyset id and, for a value's data key, the IV and
// field descriptor) is bound to every wrapped key. AWS KMS binds it as the
// encryption context, which CloudTrail logs and key policies can test.
// Google Cloud KMS binds it as additional authenticated data. Vault Transit
// and Azure Key Vault wrap a key with a digest of it, which the guest checks
// after the unwrap; a derived Transit key also gets it as its derivation
// context. Azure does not see the binding. [StaticKey] offers derived data
// keys only, and nothing outside the process can refuse or audit its use.
//
// A rewrap of a keyset record (stash keyset rewrap) does not re-key stored
// values. Under wrapped data keys, a rewrap to another vendor key makes the
// values sealed before it fail to open; a new version of the same key is
// safe. The stack-kms-vendor crate documentation has the full capability
// matrix: credentials, rotation and known limits of each backend.
//
// A vendor keyset refuses ZeroKMS-only features (a lock context, a
// decryption policy) with an error; it never ignores one. A vendor failure
// reads as the ZeroKMS one of the same kind: [ErrForbidden] for a refused
// request or bad credentials, [ErrNotFound] for a missing key, [ErrTransport]
// for an unreachable vendor, a throttle that outlasted the retries or a
// failed credential source (whose own error errors.Is also matches), and
// [ErrAuthentication] for a wrapped key that does not open. The
// [*Diagnostic]'s code is "stack_kms::backend", and its "vendor" field names
// the backend.
//
// # Errors
//
// The generator and the compiler find a mistake in a declaration, so no call
// returns an error for one. A call returns an error for a key, for the
// network, or for stored data: [ErrForeignKeyset] when a *Cipher is given a
// record another keyset sealed, [ErrAuthentication] or [ErrForbidden] for a
// ciphertext that does not open under its field's context, [ErrEncoding] for
// a stored value that does not fit its declaration. Read the kind with
// errors.Is, and the detail behind a failure the engine reports (its code,
// help, structured fields and causes) with errors.As into a [*Diagnostic].
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
// Between calls the guest holds the client key and its keyset cache. Data
// keys are per-call values, wiped when the export returns, and every buffer
// staged for a call is wiped before the call's result is returned. One
// exception remains: after Decrypt, one unwiped copy of each opened string
// stays in the guest's freed heap until that memory is reused. The test
// TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt records the gap and is
// skipped until vitaminc wipes that copy.
package encrypt
