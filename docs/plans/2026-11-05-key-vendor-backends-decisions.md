# Key vendor backends: decision log (CIP-5203)

The design is in ADR-0009, ADR-0010 and ADR-0011
(`packages/stack-encrypt/docs/adr/`) and in the CIP-5203 sub-issues. This
file records the decisions made **during implementation without asking**, so
that they can be revised later. Each entry names the ticket, the decision,
the alternatives and the reason.

## Stack structure

- **Decision:** the work is one stack of pull requests on `main`. The design
  PR (#1521, ADRs and `CONTEXT.md`) is the bottom layer, rebased onto the
  latest `origin/main`, so every code layer can refer to the ADRs.
  **Alternative:** keep #1521 outside the stack. **Reason:** the code layers
  cite the ADRs and glossary terms.
- **Decision:** the layer order is CIP-5304 (trait), CIP-5305 (v2 leaf),
  CIP-5306 (keyset records, modes, static), CIP-5307 (AWS), CIP-5310 (Vault),
  CIP-5308 (GCP), CIP-5309 (Azure), CIP-5311 (Go), CIP-5312 (`stash keyset`),
  CIP-5313 (docs). **Reason:** AWS and Vault have local emulators (LocalStack,
  `vault server -dev`), so they prove the vendor transport before the two
  vendors that have only recorded fixtures.

## CIP-5304: Make DataKeySource and IndexKeySource vendor-neutral

- **Decision:** the trait signatures of `DataKeySource` and `IndexKeySource`
  do not change. The payload structs keep their ZeroKMS fields (`context`,
  `decryption_policy`, the `KeyId` iv) and the `UnverifiedContext`
  argument stays. New: `ZeroKmsFeature`, the `ZeroKmsExtensions` trait on
  both payloads, `refuse_zerokms_extensions(vendor, payloads,
  unverified_context)`, and neutral accessors (`descriptor()`,
  `iv_bytes()`). A key vendor backend calls the refusal first in each
  method and gets `Error::ZeroKmsOnly { vendor, feature }`.
  **Alternative:** remove the ZeroKMS types from the payloads and the
  trait methods. **Reason:** that breaks 22 implementations (stack-encrypt
  tests, the Go guest tests, the EQL encryption tests) for no gain in
  safety. A backend can ignore a public field either way; the refusal
  helper is what makes "refuse, never ignore" easy to do. The ticket text
  says "remove"; this is the weaker reading, chosen with the orchestrator's
  guidance.
- **Decision:** an empty key context and an empty `UnverifiedContext` are
  not ZeroKMS features, and a key vendor backend accepts them.
  **Alternative:** refuse `Some(empty)`. **Reason:** they bind nothing.
  stack-encrypt always sends an empty context and `None`.
- **Decision:** the key lifetime comes from a new provided method,
  `IndexKeySource::load_index_key_with_lifetime`, which returns
  `LoadedIndexKey { keyset_id, key, lifetime }`. The default
  implementation calls `load_index_key` and returns
  `KeyLifetime::UntilEvicted`. The cipher calls only the new method.
  **Alternative:** change the return type of `load_index_key`.
  **Reason:** additive; every existing source keeps the ZeroKMS behaviour
  with no edit. A wrapper that forwards only `load_index_key` reports
  `UntilEvicted`, which is correct for every wrapper in the tree today.
- **Decision:** `KeyLifetime` is `Settle`, `Ttl(Duration)` and
  `UntilEvicted` (the default), `#[non_exhaustive]`. `Ttl(ZERO)` is the
  same as `Settle`. A TTL past the range of `Instant` is `UntilEvicted`. A
  lifetime the cipher does not know is never cached. **Reason:** the short
  answer is the safe one.
- **Decision:** the cipher enforces the lifetime in `KeysetCache`
  (`KeysetState.retention`). A `Settle` key is never inserted: each
  `StackCipher::keyset` call loads it again, and the `KeysetCipher` handle
  (and the pendings built from it) holds the only reference. A TTL key is
  evicted on the first lookup at or after its end, and every insert sweeps
  out all expired entries. Expiry raises the watermark as LRU eviction
  does. **Alternative:** load the index key inside each settle.
  **Reason:** term derivation is synchronous and reads `KeysetCipher::prf`
  while the target is built, before the settle. Moving the load into the
  settle changes the public `Term`/`Pending` shape. So in this layer "one
  settle" means "one keyset selection": a caller that keeps a handle keeps
  the key. The docs on `StackCipher::keyset` say so.
- **Decision:** `StackCipherBuilder::init` refuses a default keyset whose
  lifetime is not `UntilEvicted`, with the new
  `stack_encrypt::Error::DefaultKeysetLifetime { keyset }`
  (`stack_encrypt::default_keyset_lifetime`). **Alternative:** keep the
  default anyway, or make `default_keyset()` async. **Reason:**
  `default_keyset()` is synchronous and holds the default for the life of
  the cipher, so the cipher cannot obey a shorter lifetime. Refusing is
  "refuse, never ignore". Changing `default_keyset()` is a public API break.
- **Decision:** `stack_kms::Error::Backend { vendor: &'static str, kind:
  BackendErrorKind, source }` has one code, `stack_kms::backend`, and the
  payload fields `vendor` and `kind`. `BackendErrorKind` is `NotFound`,
  `AccessDenied`, `Throttled`, `Unavailable`, `InvalidCiphertext`,
  `#[non_exhaustive]`. The message is only the vendor and the kind.
  **Alternative:** one code per kind; a vendor enum. **Reason:** the miette
  derive gives one code per variant, and the kind is in the payload. A
  vendor enum would fix the vendor list before CIP-5305 numbers the v2
  leaf's backend byte.
- **Decision:** `Error::Backend` and `Error::ZeroKmsOnly` are new variants of
  the exhaustive `stack_kms::Error`. That is a breaking change for a caller
  that matches it exhaustively (the Go guest's `status_for_kms` did). The
  commit is marked breaking (`!`) so release-plz bumps stack-kms 0.1 to
  0.2. **Alternative:** make `Error` `#[non_exhaustive]` now. **Reason:**
  the guest relies on exhaustiveness on purpose (see `status.rs`).
- **Decision:** the Go guest maps `Backend` kinds: `NotFound` to
  `STATUS_KMS_NOT_FOUND`, `AccessDenied` to `STATUS_KMS_FORBIDDEN`,
  `Throttled` and `Unavailable` to `STATUS_KMS_TRANSPORT`,
  `InvalidCiphertext` to `STATUS_AUTH`; `ZeroKmsOnly` to `STATUS_ENCODING`.
  **Reason:** the nearest existing status for each. CIP-5311 can revisit.
- **Decision:** `IndexKey::from_key_bytes(Protected<[u8; 32]>)` is the
  public constructor from raw key material. `From<Key>` stays
  `test-support` only. **Reason:** `Protected` wipes the caller's copy on
  drop and does not print.
- **Decision:** `is_keyset_not_found` also matches `Error::Backend { kind:
  NotFound }`, so a key vendor backend's "no such keyset" forgets a name
  binding as ZeroKMS's does.
- **Decision:** `Descriptor::MAX_LEN` is the literal `512`, with a test that
  it equals `stack_kms::MAX_DESCRIPTOR_LEN`. The `DescriptorTooLong` message
  and help say "key descriptor" and "a key backend", not "ZeroKMS".
  **Reason:** the limit stays the same for every backend; only the source
  of the constant moves.
- **Decision:** `CONTEXT.md` gets a glossary entry for **key lifetime**.
- **Deferred to CIP-5306:** the rule "a cipher holds ZeroKMS and at most one
  key vendor backend, a second vendor is a typed error". The trait layer
  has no notion of vendor yet (a cipher holds one `K`), so there is nothing
  to enforce until the builder takes a key vendor backend beside ZeroKMS.
- **Deferred to CIP-5306:** how a key vendor backend's default keyset is
  chosen, given that `init` refuses a default with a short lifetime.
- **Deferred (no ticket yet):** binding a `Settle` index key to exactly one
  settle inside a held `KeysetCipher` handle (see above).
- **Note:** `stack-encrypt::ui derive_diagnostics` (trybuild) fails on this
  machine on the base commit too: the snapshots print relative paths and
  the local run prints `<HOME>/…` paths. It is not caused by this change.

## Orchestrator review of CIP-5304

- **Decision:** accept that, in CIP-5304, a `Settle` key lifetime lasts as
  long as one keyset selection (one `KeysetCipher` handle), not one settle.
  **CIP-5306 must close this gap** before it ships wrapped data keys: for a
  keyset whose index key has the `Settle` lifetime, the term PRF runs inside
  the settle (the deferred-backend path that `sem/mod.rs` already describes),
  and the handle does not hold the index key. **Alternative:** send CIP-5304
  back. **Reason:** the gap matters only once a backend returns `Settle`, and
  no backend does until CIP-5306. ADR-0009's "no key outlives the settle that
  needed it" is the target, and it is unchanged.
- **Decision:** accept that the trait signatures and payload fields keep their
  ZeroKMS types, and that a vendor backend refuses them through
  `refuse_zerokms_extensions`. **Alternative:** remove the types now, which
  breaks 22 implementations. **Reason:** the refusal is what ADR-0009 needs,
  and the change is additive. Revisit when TypeScript (CIP-5314) moves onto
  stack-encrypt.
- **Note:** `stack-encrypt::ui derive_diagnostics` (trybuild) fails on `main`
  on a developer machine whose paths print as `<HOME>`. It is not caused by
  this stack. CI is the judge.

## CIP-5305: v2 sealed leaf with key backend and key mode

- **Decision:** the backend and mode are two `stack-kms` enums, `KeyVendor`
  and `KeyMode`, with stable bytes. `KeyVendor`: `Aws = 1`, `Gcp = 2`,
  `Azure = 3`, `Vault = 4`, `Static = 5`. `KeyMode`: `Wrapped = 1`,
  `Derived = 2`. The value `0` is invalid for both, so a zeroed header
  never decodes. A value is never reused. `KeyBackend` is `ZeroKms` or
  `Vendor(KeyVendor)`, so ZeroKMS has no backend byte and a v2 leaf cannot
  name it. **Alternative:** one enum with a ZeroKMS byte; the enums in
  `stack-encrypt`. **Reason:** the trait method (below) lives in
  `stack-kms` and must return the type. Leaving ZeroKMS out of the byte
  enum makes "ZeroKMS is never v2" a type fact.
- **Decision:** `KeyVendor` is `#[non_exhaustive]`; `KeyMode` and
  `KeyBackend` are exhaustive. **Reason:** a new vendor is likely; ADR-0009
  rejects a third mode, and `KeyBackend` has exactly two shapes.
- **Decision:** `KeyVendor::name()` gives stable names (`aws-kms`,
  `gcp-kms`, `azure-key-vault`, `vault-transit`, `static`), and a key
  vendor backend should use it as the `vendor` of `Error::Backend` and
  `Error::ZeroKmsOnly`. `KeyBackend::ZeroKms` is `zerokms`.
- **Decision:** the seam is a provided method,
  `DataKeySource::key_backend(&self) -> KeyBackend`, default `ZeroKms`.
  **Alternative:** a method on `IndexKeySource`, or a per-keyset answer.
  **Reason:** additive; every existing source keeps ZeroKMS with no edit,
  and ADR-0010 routes a leaf by the backend the cipher holds, not by the
  keyset. A wrapper must forward it (the doc says so); no wrapper in the
  tree needs to today.
- **Decision:** `SealedValue` keeps one type and gains a private
  `vendor: Option<VendorHeader>` field. `None` is v1. New API:
  `VENDOR_FORMAT_VERSION = 2`, `format_version()`, `key_backend()`,
  `key_mode()`, `from_vendor_parts(vendor, mode, keyset_id, iv, tag, ct)`.
  `FORMAT_VERSION` stays `1` and still names v1. `into_parts` is
  unchanged and drops the v2 header (documented: persist v2 with
  `to_bytes`). **Alternative:** a separate v2 type, or an enum leaf.
  **Reason:** every tree, visitor and binding carries `SealedValue`; one
  type keeps v2 opaque to all of them.
- **Decision:** the serde form of a v1 leaf does not change. A v2 leaf
  adds a last field `vendor: [backend, mode]`, skipped when `None` and
  defaulted on read. **Reason:** keeps stored v1 serde data readable; no
  caller in the tree uses serde for leaves.
- **Decision:** the leaf AAD's second PAE piece is the envelope header:
  `[0x01]` for v1 (byte for byte the old AAD; the existing pin is
  unchanged) and `[0x02, backend, mode]` for v2. **Alternative:** two
  extra PAE pieces for v2. **Reason:** PAE frames each piece with its
  length, so a 3-byte header can never collide with a 1-byte one, and the
  v1 derivation stays identical. A new pin covers the v2 AAD.
- **Decision:** the routing refusal is
  `stack_encrypt::Error::ForeignBackend { expected, found }`
  (`stack_encrypt::foreign_backend`), raised in `dispatch` before any
  generate or retrieve call, for any retrieve whose leaf names another
  backend than `cipher.kms().key_backend()`. It is symmetric: a vendor
  cipher refuses a v1 leaf too. Each retrieve `Request` now carries the
  leaf's backend; the new public `Request::retrieve_leaf_key(&leaf,
  context)` sets it, and the old `retrieve_data_key` names ZeroKMS.
  **Alternative:** check in `check_scope` at pending construction.
  **Reason:** `check_scope` has no cipher; `dispatch` is the one gate
  every request passes before I/O, and the refusal is still before any
  key call. A whole tree is refused if one leaf is foreign.
- **Decision:** a generate request under a key vendor backend is refused
  with `stack_encrypt::Error::SealUnsupported { backend }`
  (`stack_encrypt::seal_unsupported`), before any key call. **Alternative:**
  write v1 (it would name ZeroKMS, wrongly) or wire v2 sealing now.
  **Reason:** the v2 seal needs the keyset's key mode, which is CIP-5306's
  keyset record. The private `seal_leaf_as(Some(header), ..)` already
  writes v2; the tests use it.
- **Decision:** `LeafBytesError` gains `UnknownBackend(u8)`
  (`stack_encrypt::leaf_backend`) and `UnknownMode(u8)`
  (`stack_encrypt::leaf_mode`). A v1-only reader (an older build) refuses
  v2 with `UnknownVersion(2)`, as ADR-0010 says.
- **Decision:** the Go guest maps `ForeignBackend` to `STATUS_ENCODING`
  (the caller's input; no keyset option opens it, so not
  `STATUS_FOREIGN_KEYSET`). `SealUnsupported` falls to `STATUS_INTERNAL`
  (the guest holds ZeroKMS, so it cannot occur). CIP-5311 can revisit.
- **Decision:** a v1 known-answer test (`a_pinned_v1_leaf_still_opens` in
  `tests/frozen_bytes.rs`) pins the bytes of a real v1 leaf sealed under
  `DeterministicSource([7; 32])` and opens it. The existing layout pin
  (`sealed_value_layout_is_pinned`) is unchanged.
- **Decision:** `eql-bindings` needs no code change. Its `c` is still
  `stack-encrypt:1:` + base64 of `SealedValue::to_bytes`; the `1` there is
  the EQL producer marker, not the leaf version. A new test
  (`a_v2_leaf_passes_through_the_ciphertext_as_opaque_bytes`) proves a v2
  leaf round-trips through `c`.
- **Decision:** fuzzing reuses the `sealed_value_decode` target (it already
  checks "no panic" and "lossless" for every input) and adds two v2 seeds
  (`valid-leaf-v2-aws-wrapped`, `valid-leaf-v2-static-derived-empty-tag`).
  The seed replay and a 30 s run passed.
- **Deferred to CIP-5306:** the v2 seal path (choose the leaf header from
  the keyset's backend and key mode), and passing the leaf's key mode to
  the key source on retrieve (`RetrieveKeyPayload` does not carry it yet;
  the cipher has it in `SealedValue::key_mode`). Remove or keep
  `Error::SealUnsupported` then.
- **Deferred to CIP-5306:** a cipher that holds ZeroKMS and one key vendor
  backend routes each leaf to the right one. Today a cipher holds one `K`,
  so `ForeignBackend` compares with that one backend.

## CIP-5306: Keyset records, the two key modes, and the static key backend

- **Decision:** the vendor code lives in a new crate,
  `packages/stack-kms-vendor` (`stack-kms-vendor`), in the root workspace.
  It depends on `stack-kms` only (plus `stack-encrypt` behind its
  `test-support` feature, for the contract suite). It is `publish = false`
  and listed in `release-plz.toml` with `release = false`.
  **Alternative:** put it in `stack-kms`. **Reason:** `stack-kms` is the
  ZeroKMS client; the vendor seam, records, HKDF and AES-GCM are a separate
  concern, and each vendor crate depends on this one crate.
  **Deferred to CIP-5307:** decide its release group and publish it with
  the first vendor crate, which cannot publish while it depends on an
  unpublished crate.
- **Decision:** the vendor seam is the trait `KeyVendorBackend`: `vendor()`,
  `supports_mode(mode)` (default both), `wrap(key_ref, key, aad)`,
  `unwrap(key_ref, wrapped, aad)`, `generate_wrapped(key_ref, aad)`
  (default: a CSPRNG key and one `wrap`) and `sleep(duration)` (default:
  return at once). Keys are `KeyBytes = Protected<[u8; 32]>`. A vendor
  reports failures as `stack_kms::Error::Backend` with `KeyVendor::name()`.
  The adapter `VendorKeySource<B>` implements `DataKeySource` and
  `IndexKeySource` on it, so a vendor crate never touches those traits.
  **Reason:** the user named the term "key vendor backend"; the trait is
  the smallest thing all four vendors can do.
- **Decision:** a vendor with no native associated data (Azure Key Vault
  RSA wrap) must bind `aad` itself, for example by wrapping
  `SHA-256(aad) ‖ key`. The trait docs say so. **Deferred to CIP-5309.**
- **Decision:** the keyset record text form is `stack-keyset:` + unpadded
  base64url of `version(1)=1 ‖ backend(1) ‖ mode(1) ‖ keyset id(16) ‖
  name len(1, 0 = none) ‖ name ‖ key ref len(2, BE) ‖ key ref ‖ wrapped
  len(2, BE) ‖ wrapped key`. Parsing refuses an unknown version, backend
  or mode, a length mismatch, an empty or over-long field and invalid
  UTF-8. A test pins the text of one record. **Alternative:** CBOR or
  JSON. **Reason:** a fixed binary layout has one encoding per record, no
  new dependency, and the backend and mode bytes are the v2 leaf's.
- **Decision:** the wrapped key in a record is bound with associated data
  `frame["stack-kms-vendor/keyset-record-key/v1", purpose, keyset id,
  vendor byte, mode byte]` (purpose `root-key` or `index-key`). A record
  edited in its id, backend or mode does not unwrap. The name is not
  bound: it is a local label, renamed by editing the record. The key ref is
  not bound: the vendor key itself is the binding.
- **Decision:** keyset names resolve locally from the loaded records, with
  no freshness window. Duplicate ids or names are refused at load.
- **Decision:** record creation is `KeysetRecord::create(&backend, key_ref,
  mode, name)` (one vendor call; generates the keyset id and the key) and
  `KeysetRecord::rewrap(&backend, new_key_ref)` (two calls; id, name and
  mode stay). **Decision (open item of the ticket):** `stash` (TypeScript)
  calls these through a Rust helper, not the vendor JS SDKs: a napi
  function in a node binding (the way `@cipherstash/auth` ships), so the
  request signing code exists once, in Rust. **Deferred to CIP-5312.**
- **Decision:** framing for every label, info and associated data is
  `frame(pieces)` = piece count, then each piece's length and bytes, all
  lengths `u64` little-endian. Pinned by tests.
- **Decision:** derived data keys: data key = `HKDF-SHA256(ikm = root, salt
  = iv, info = frame["stack-kms-vendor/derived-data-key/v1", keyset id,
  descriptor])`; index key = `HKDF-SHA256(ikm = root, salt = none, info =
  frame["stack-kms-vendor/derived-index-key/v1", keyset id])`. The iv is
  16 random bytes per value; the tag is empty, and a retrieve refuses a
  non-empty tag. The `hkdf` 0.13 crate (RFC 5869 test vector pinned) and
  `sha2` 0.11 are new dependencies. Both derivations are pinned.
- **Decision:** wrapped data keys: each value's data key is a vendor
  `generate_wrapped` under associated data `frame["stack-kms-vendor/
  wrapped-data-key/v1", keyset id, iv, descriptor]`; the wrapped key is
  the leaf's tag. The iv is 16 random bytes.
- **Decision:** the default root key TTL is **5 minutes**
  (`DEFAULT_ROOT_KEY_TTL`), set with `with_root_key_ttl`; `Duration::ZERO`
  keeps none. The adapter, not the cipher, holds the root key, and drops
  every expired root key on each lookup. A throttled record unwrap is
  retried with the batch backoff.
- **Decision (closes the CIP-5304 gap):** a vendor keyset is never given to
  the cipher as an index key. New `IndexKeySource::select_keyset` returns
  `SelectedKeyset::Loaded(LoadedIndexKey)` (the default, ZeroKMS) or
  `SelectedKeyset::PerSettle { keyset_id }` (the vendor adapter, both
  modes, no vendor call). For a per-settle keyset the `KeysetState` holds
  no PRF, so the handle holds no key. A term built through it pushes a new
  internal request kind (`IndexKeyForSettle`); `dispatch` loads the index
  key once per keyset per settle through the new provided method
  `DataKeySource::load_settle_index_key`, keeps the PRF in the
  `Responses`, and drops it (wiping the key) when the settle ends. Under
  wrapped data keys that is one vendor unwrap per settle; under derived
  data keys it is an HKDF from the cached root key. **Nothing outlives a
  settle** in either mode except, under derived data keys, the root key in
  the adapter for its TTL, which is the ADR-0009 trade-off.
  **Alternative:** keep the CIP-5304 behaviour (the handle holds the key).
  **Reason:** the orchestrator review made this binding.
- **Decision:** the term derivations run inside the settle through a
  recording PRF backend (`sem/capture.rs`): a term's source may borrow, so
  at build time the value is run against a backend that records every leaf
  call (bytes, encoding, fully derived context) and the shape of every
  sequence and map, owned; inside the settle the recording replays into the
  real HMAC PRF through its own drivers. Tests show replay equals direct
  derivation for every `vitaminc-prf` shape, and that a per-settle cipher
  derives the same equality, match, ORE and OPE terms as a cipher that
  holds the same key. The one assumption: a `PrfValue` passes its visitor
  through unchanged (all `vitaminc-prf` impls do). Match terms copy the
  text into a `Zeroizing<String>`; ORE and OPE sources are already owned.
- **Decision (breaking, stack-encrypt):** `KeysetCipher::prf()` now returns
  `Option<&HmacSha256Prf>`: `None` for a per-settle keyset. The commit is
  marked `!`. **Alternative:** keep `&HmacSha256Prf`. **Reason:** a
  per-settle handle has no PRF to return; returning a fake one would make
  terms that match nothing. No caller in the tree used it outside `sem`.
  An outside term type cannot defer yet (`Responses::index_prf` is
  crate-private); revisit if a caller needs it.
- **Decision:** the default keyset question: `init` accepts a per-settle
  default keyset (it holds no key, so there is nothing to outlive). For a
  vendor-only cipher (`StackCipher::builder().kms(VendorKeySource)`), the
  default is the only record when there is exactly one, else the one set
  with `with_default_keyset(id)`; with neither, `init` fails `NotFound`.
  Under `KeyRouter` the default keyset is ZeroKMS's default.
  `Error::DefaultKeysetLifetime` stays for a source that loads a short-lived
  key eagerly.
- **Decision:** new provided methods on `DataKeySource`:
  `keyset_backend(keyset_id)` (default `key_backend()`), `key_mode(keyset_id)`
  (default `None`) and `load_settle_index_key(keyset_id)` (default refuses
  with `Error::Unexpected`). New pub field `RetrieveKeyPayload::key_mode`
  and `with_key_mode`. Additive except that a struct-literal construction
  of `RetrieveKeyPayload` breaks; stack-kms already takes a breaking bump in
  this stack (CIP-5304), so the field rides on it.
- **Decision:** `dispatch` now asks `keyset_backend` per keyset: a leaf is
  refused (`ForeignBackend`) when it names another backend than the one
  that holds its keyset, and a settle seals v2 with the keyset's mode when
  a key vendor backend holds the pending's keyset. The leaf's mode goes to
  the key source on retrieve, and the adapter refuses a mode that is not
  its keyset's (`Backend { kind: InvalidCiphertext }`).
- **Decision:** `Error::SealUnsupported` stays. It now means "a key vendor
  backend holds the keyset but names no key mode for it", which is the one
  case where the cipher cannot choose the leaf header.
- **Decision:** routing between ZeroKMS and one vendor is `KeyRouter<Z, B>`
  in `stack-kms-vendor`. A keyset id or name that a vendor record has goes
  to the vendor (a local record name wins over a ZeroKMS keyset of the same
  name); everything else, and the default keyset, goes to ZeroKMS. The type
  holds exactly one vendor; `VendorKeySource::new` refuses records of two
  vendors with `RecordError::SecondVendor`, and a record of another vendor
  than the backend with `RecordError::ForeignVendor`.
- **Decision:** the static key backend (`StaticKeyVendor`) wraps with
  AES-256-GCM under a random 96-bit nonce: `version(1)=1 ‖ nonce(12) ‖
  ciphertext ‖ tag`. It holds several keys by reference, for rotation.
  `supports_mode` is derived only: `KeysetRecord::create` refuses wrapped
  (`ModeUnsupported`), and so does `VendorKeySource::new` for a record that
  names it. It uses `aes-gcm` 0.10.3, already in the lockfile.
- **Decision:** batching is `run_batch(options, count, call, sleep)`:
  `buffered` (order kept) with `BatchOptions { concurrency: 16,
  max_attempts: 5, base_delay: 50 ms, max_delay: 2 s }`, exponential
  backoff on `Throttled` only, and the first other failure (or a call still
  throttled after the last attempt) fails the whole batch. It has no timer
  of its own: the vendor's `sleep` is the timer, so it runs on native Rust
  and in the WASI guest alike.
- **Decision:** the vendor transport is `VendorTransport { send(VendorRequest)
  -> VendorResponse, sleep(Duration) }`, futures bounded by `MaybeSend`, the
  shape of `ZeroKMSConnection`, plus `classify_status` (401/403
  AccessDenied, 404 NotFound, 429 Throttled, 5xx Unavailable, other 4xx
  InvalidCiphertext). No vendor uses it yet. **Deferred to CIP-5307:** the
  native (reqwest) implementation and the guest's `transport_send`
  implementation.
- **Decision:** the contract suite is `stack_kms_vendor::contract` (feature
  `test-support`): `contract::run(make_backend, key_ref)` runs every check
  for each mode the vendor offers, through `VendorKeySource` and a real
  `StackCipher`. `Observed<B>` wraps any backend to count calls and inject
  throttles, so lifetime, batching and backoff are tested on every vendor.
  It runs here against `StaticKeyVendor` and `FakeVendor` (an in-memory
  vendor, both modes, reported as AWS and Vault). Real-time TTL expiry is
  tested once, here, with tokio.
- **Decision:** `mise run wasm:wasi-check` now also checks
  `stack-kms-vendor` (no JS-host or native-HTTP dependency on WASI), and
  `tests-crates.yml` and `udeps.yml` include its path.
- **Note:** the Go guest still compiles for wasm32-wasip1 with and without
  `--features eql`. It does not use a key vendor backend yet (CIP-5311).
- **Note:** `scripts` vitest: `bench-index-expressions` and
  `check-auth-npm-changeset` fail on this machine for missing
  `node_modules` content, with or without this change.
