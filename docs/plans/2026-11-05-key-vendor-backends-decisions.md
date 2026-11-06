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

## CIP-5307: AWS KMS key vendor backend (stack-kms-aws)

### Transports

- **Decision:** the native `VendorTransport` is `HttpVendorTransport` in
  `stack-kms-vendor`, behind a new feature `http`, with its dependencies
  (reqwest, stack-auth with `http`, tokio `time`) gated to non-wasm32
  targets. It uses the workspace reqwest and `stack_auth::tls::client_config`,
  the same HTTP client and TLS verifier as stack-kms's `HttpConnection`.
  `sleep` is `tokio::time::sleep`. A transport failure text leaves out
  reqwest's own message, which names the URL.
  **Alternative:** put it in `stack-kms-aws`, or in `stack-kms`.
  **Reason:** every vendor crate needs the same transport, so it belongs
  beside the seam. The target gate keeps `stack-kms-vendor --features http`
  clean on WASI (the `wasm:wasi-check` task now checks that).
- **Decision:** the guest `VendorTransport` is `HostVendorTransport` in
  `stack-guest-abi`, module `vendor_transport`, behind a new feature
  `vendor`. The type exists on wasm32 only; the conversions (headers to the
  `transport_send` line format, a negative status to `TransportError`) are
  pure functions with native unit tests. A header with a line break, or a
  name with a colon, is refused (header injection). `sleep` is
  `std::thread::sleep`, which wasm32-wasip1 implements with a `poll_oneoff`
  clock subscription; the guest runs one call at a time, so blocking is
  correct. **Alternative:** in `stack-kms-vendor` (a published crate cannot
  depend on the unpublished `stack-guest-abi`), or in the Go guest crate (a
  detached workspace with no native tests, and that wiring is CIP-5311).
  **Reason:** `stack-guest-abi` already owns the import.
- **Decision (changes a CIP-5306 type):** `VendorRequest::body` and
  `VendorResponse::body` are now `Zeroizing<Vec<u8>>`, and their `Debug`
  shows the method, URL, status and header names only. Both types gain small
  builders (`new`, `header`, `body`, `header_value`). **Reason:** an AWS
  `Encrypt` request and a `Decrypt` response carry a key in the clear, and a
  session token travels in a header. The crate is unpublished, so the break
  costs nothing. reqwest takes the body by value, so its copy is not wiped
  (as for ZeroKMS).

### The AWS KMS client

- **Decision:** `stack-kms-aws` is a new root workspace member with
  `AwsKms<T: VendorTransport, C: CredentialsProvider>`, which implements
  `KeyVendorBackend` only: `wrap` is `Encrypt`, `unwrap` is `Decrypt` (with
  `KeyId`, so AWS KMS also checks the key), `generate_wrapped` is one
  `GenerateDataKey` (`AES_256`), and `sleep` is the transport's. Both key
  modes. `key_ref` is a key ARN (a key id or alias ARN also works; the docs
  recommend the key ARN, because an alias can be repointed). `send_json` is
  public, so a test (and later `stash keyset`) can send another operation,
  for example `CreateKey`.
- **Decision:** SigV4 is written in the crate (`stack_kms_aws::sigv4`) with
  `hmac` 0.13 and `sha2` 0.11, both already in the lockfile (through `hkdf`).
  No `aws-sigv4` and no AWS SDK crate. **Alternative:** the `aws-sigv4`
  crate. **Reason:** it pulls the smithy runtime crates; the algorithm is
  about 150 lines and is pinned by test vectors. Its build for
  wasm32-wasip1 was not tried. `sign` signs every header the request has,
  and adds `host`, `x-amz-date`, `x-amz-security-token` and
  `authorization`. It does not add `x-amz-content-sha256` (AWS KMS does not
  need it).
- **Decision:** the SigV4 vectors are, from the AWS SigV4 test suite
  (`aws-sig-v4-test-suite`): `get-vanilla`, `post-vanilla`,
  `get-vanilla-query-order-key-case` and `post-x-www-form-urlencoded` (a POST
  with a body); and the worked IAM `ListUsers` example of the AWS SigV4
  documentation (canonical request hash and signature). All were written
  from memory, and all passed on the first run, which checks the memory and
  the code against each other. AWS publishes no KMS signing example that I
  could reproduce reliably; the KMS request shape is pinned by the recorded
  fixtures instead.
- **Decision:** the associated data is bound as the AWS KMS encryption
  context: `cipherstash:aad` = unpadded base64url of all of `aad` (this is
  the binding), plus, when `aad` is a keyset record key or a wrapped data
  key, `cipherstash:purpose` (`root-key`, `index-key`, `data-key`),
  `cipherstash:keyset-id` and `cipherstash:descriptor` (left out when
  empty). New in `stack-kms-vendor::derive`: `unframe` and `describe_aad`
  (`AadDescription`), so the shared crate owns the parse of its own format.
  **Alternative:** the readable fields only (they leave out the iv, vendor
  and mode, so they do not bind the whole aad), or `cipherstash:aad` only
  (nothing readable in CloudTrail or for `kms:EncryptionContext:` policy
  conditions). **Reason:** both properties.
- **Decision:** error mapping. The code comes from the body's `__type`
  (namespace before `#` removed), else the `x-amzn-ErrorType` header (text
  after `:` removed). The ticket's list, plus: `IncorrectKeyException` and
  `InvalidKeyUsageException` to `InvalidCiphertext`; the signature and
  token codes (`UnrecognizedClientException`, `InvalidSignatureException`,
  `ExpiredTokenException`, ...) to `AccessDenied`; `DisabledException`,
  `KMSInvalidStateException`, `KeyUnavailableException` to `Unavailable`.
  A code with no fixed kind falls back to `classify_status`, but an unknown
  4xx code is `AccessDenied`, not `InvalidCiphertext` (for example a
  `ValidationException` is a refused request, not a damaged value).
  `LimitExceededException` is not `Throttled`: it is a resource quota, and a
  retry does not help. A success that cannot be read is `Unavailable`; a
  plaintext that is not 32 bytes is `InvalidCiphertext`. No transport,
  credential or response failure carries key material or a secret.
- **Decision:** region from the config, else `AWS_REGION`, else
  `AWS_DEFAULT_REGION`; endpoint from `with_endpoint`, else
  `AWS_ENDPOINT_URL_KMS`, else `AWS_ENDPOINT_URL` (the AWS SDK names), else
  `https://kms.<region>.amazonaws.com/` (`.com.cn` for `cn-` regions). A
  region must be `[a-z0-9-]`, so it cannot change the endpoint host.
- **Decision:** `Clock` (`Arc<dyn Fn() -> SystemTime>`) is a seam on
  `AwsKms` and `CachedCredentials`, for fixtures with a fixed signing time.

### Credentials

- **Decision:** the seam is the trait `CredentialsProvider` (future bounded
  by `MaybeSend`); `Credentials` (secret and token wiped, never printed) is
  the static provider, from `Credentials::new` or `Credentials::from_env`.
  The guest implements the trait over a host import (CIP-5311).
- **Decision:** `CachedCredentials<P>` refreshes 5 minutes before expiry
  (`DEFAULT_REFRESH_BEFORE_EXPIRY`), one fetch at a time (an async mutex),
  and returns the cached credentials when a refresh fails but they have not
  yet expired. Credentials with no expiry are kept.
- **Decision:** workload identity is native only (`cfg(not(target_arch =
  "wasm32"))`): `WebIdentityCredentials` (STS `AssumeRoleWithWebIdentity`,
  unsigned, form POST, the token file read on each fetch, the regional STS
  endpoint, XML read by tag), `EcsCredentials` (relative or full URI; a full
  URI must be HTTPS or HTTP to a loopback or the ECS/EKS link-local hosts,
  as the AWS SDKs require; the token from
  `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, read on each fetch, or
  `AWS_CONTAINER_AUTHORIZATION_TOKEN`), and `ImdsCredentials` (IMDSv2 only;
  `AWS_EC2_METADATA_DISABLED`, `AWS_EC2_METADATA_SERVICE_ENDPOINT`). They
  send through `VendorTransport` too, so the fixtures test them.
- **Decision:** `DefaultCredentialsSource` picks one source from the
  environment, in the AWS SDK order (static, IRSA, container, IMDS), by
  which variables are set, not by trying each. `AwsKms::from_env`
  (`DefaultAwsKms`, feature `http`, native) caches it, and gives the
  credential sources their own transport with a 1 s connect limit so that
  the IMDS probe fails fast off EC2. **Not supported:** the shared config
  and credentials files (`~/.aws/config`), profiles, SSO and
  `credential_process`. No ticket asks for them.

### Tests

- **Decision:** recorded fixtures (`tests/fixtures/*.json`) for
  `GenerateDataKey`, `Encrypt`, `Decrypt` and `Decrypt` with a session
  token, and eleven error responses. The responses are written in the AWS
  response shapes; each request side (body, headers, signature) was taken
  from the client once and is now pinned. Every fixture is signed at
  2026-11-05T12:00:00Z with the AWS documentation example key.
- **Decision:** the contract suite runs against `AwsKms` over an in-process
  emulation of the AWS KMS JSON API (`tests/common::KmsEmulator`: AES-GCM
  with the encryption context bound, the AWS error shapes, a check that each
  request is signed for `kms`). **Reason:** the suite uses random keys and
  ids, so recorded bytes cannot answer it.
- **Decision:** the LocalStack test (`tests/localstack.rs`) runs when
  `STACK_KMS_AWS_LOCALSTACK_ENDPOINT` is set and skips itself otherwise. It
  creates a key with `CreateKey`, runs the whole contract suite, and checks
  three error mappings. It ran locally against `localstack/localstack:4.4`
  and passed. LocalStack answers bytes that are not its blob format with
  HTTP 500 (`InternalError`), not `InvalidCiphertextException`, so the test
  damages a real blob instead.
- **Decision:** CI: a new `localstack` job in `tests-crates.yml` runs
  LocalStack 4.4 as a service, pinned by digest, and calls the new mise task
  `test:localstack:stack-kms-aws`, which refuses to run without the
  endpoint (a skip must not read as a pass). New `doc:stack-kms-aws` and
  `doc:stack-kms-vendor` tasks join `mise run doc`. `wasm:wasi-check` now
  also checks `stack-kms-vendor --features http`, `stack-kms-aws` (default
  features) and `stack-guest-abi --features vendor`. `tests-crates.yml` and
  `udeps.yml` include the new path. `crates-ci.test.mjs` now expects seven
  crate task files.

### Publishing

- **Decision:** `stack-kms-vendor` and `stack-kms-aws` are one release
  group, `stack-kms-vendor`, which every later vendor crate joins.
  **Alternative:** a group for each crate. **Reason:** a vendor crate
  implements the seam, so a change to the seam moves every vendor.
- **Decision:** both Cargo.toml files are publishable (no `publish =
  false`) and `tests-crates.yml`'s `cargo publish --dry-run` packages both
  (it passed locally with all seven crates). In `release-plz.toml` both are
  **staged**: `version_group = "stack-kms-vendor"`, `release = false`,
  `publish = false`. `release-plz-root-config.test.mjs` and
  `cargo-publish-opt-out.test.mjs` know the staged state.
  **Alternative:** arm them now. **Reason:** crates.io Trusted Publishing can
  only be set up on a crate that exists, so the first version is published
  by hand, as it was for stack-kms. And that first publish needs the
  stack-kms and stack-encrypt of this stack on crates.io first (the vendor
  crates use their new API). Armed now, the first `release-crates` run after
  this stack merges would fail on the vendor crates.
- **To arm them (a person, after this stack's stack-kms and stack-encrypt
  are on crates.io):** `cargo publish -p stack-kms-vendor` then
  `cargo publish -p stack-kms-aws`; set up Trusted Publishing for both on
  crates.io (repository `cipherstash/stack`, workflow `release-plz.yml`);
  then a PR that removes `release = false` and `publish = false` from both
  in `release-plz.toml`, adds both to the preflight loop in
  `release-plz.yml`, and moves them from `STAGED` to `GROUPS` in
  `release-plz-root-config.test.mjs`. Update the publishing note in
  `SECURITY.md` in the same PR.
- **Decision:** no changeset. Both crates are Rust-only and released by
  release-plz.

### Deferred

- **Deferred to CIP-5311:** the guest wiring: enable `stack-guest-abi`'s
  `vendor` feature in the guest, build `AwsKms::new(config,
  HostVendorTransport, <a CredentialsProvider over the host credential
  import>)`, and map the new errors to statuses.
- **Deferred to CIP-5312:** `stash keyset` creates records through a napi
  helper; it can call `KeysetRecord::create` with `AwsKms::from_env()`.
- **Deferred (no ticket):** the AWS shared config files, profiles and SSO
  (see above).
- **Note:** `scripts` vitest still has the two failures noted in CIP-5306
  (`bench-index-expressions`, `check-auth-npm-changeset`, missing
  `node_modules` content); every other file passes.

## Orchestrator review of CIP-5307

- **Revisit:** an unknown AWS 4xx error code maps to `AccessDenied`. That
  makes a malformed request look like a permission problem. Accepted for now,
  because `AccessDenied` is never retried, so the failure is loud. A later
  change can add a `Rejected` kind if real cases appear.
- **Note:** the vendor crates are staged (`release = false`). Arming them is
  a manual step after stack-kms and stack-encrypt from this stack are on
  crates.io (see the CIP-5307 section).

## CIP-5310: HashiCorp Vault Transit key vendor backend (stack-kms-vault)

### Changes to the vendor seam (stack-kms-vendor)

- **Decision:** vendor batch calls are three new provided methods on
  `KeyVendorBackend`: `batch_limit() -> Option<NonZeroUsize>` (default
  `None`), `wrap_batch(key_ref, &[WrapItem])` and `unwrap_batch(key_ref,
  &[UnwrapItem])` (defaults: one `wrap` or `unwrap` per item). When
  `batch_limit` is `Some(n)`, `VendorKeySource` sends the wrapped data keys
  of a generate or retrieve in chunks of at most `n`, one batch call per
  chunk, and generates each data key locally with the CSPRNG. The chunks run
  through `run_batch`, so a throttled chunk backs off and is sent again
  whole, and `concurrency` limits the chunks in flight. The keyset record key
  is still one `unwrap`. **Alternative:** a Vault-only path, or a batch
  `generate_wrapped`. **Reason:** additive (AWS and the static backend change
  nothing); Transit has no batch data key operation, so local generation plus
  a batch encrypt is the only one-call form; Google Cloud KMS and Azure have
  no batch operation, so they keep the default.
- **Decision:** the contract suite forwards the batch methods in `Observed`
  (each item counts as a wrap or unwrap; `Observer::batches()` counts the
  calls) and has a new check, `uses_vendor_batches`: under wrapped data
  keys, `2n + 1` values seal and open in exactly three batch calls.
  `FakeVendor::with_batch_limit` runs the batch path in stack-kms-vendor's
  own tests.
- **Decision (the "AAD bound by us" mechanism, for CIP-5309 too):** new
  module `stack_kms_vendor::bound`. The vendor encrypts a **bound key**
  `version(1)=1 ‖ SHA-256(frame["stack-kms-vendor/bound-key/v1", aad]) ‖
  key` (65 bytes) in place of the key; `open_bound_key` checks the digest in
  constant time (`subtle`, already in the lockfile). The bytes are pinned.
  **Alternative:** AEAD-wrap the vendor ciphertext under a key derived per
  record, or carry a MAC. **Reason:** both need a second key that must come
  from somewhere (the vendor, so one more call, or the record, which then
  holds a key in the clear). The digest needs no key: it is sound when the
  vendor's encryption is non-malleable, which is true of every vendor
  encryption we use (AES-GCM, ChaCha20-Poly1305, RSA-OAEP). The module docs
  say so. 65 bytes fits RSA-OAEP-256 with a 2048-bit key. **CIP-5309 (Azure
  RSA wrap) should use it.**

### The Vault client

- **Decision:** `stack-kms-vault` is a new root workspace member with
  `VaultTransit<T: VendorTransport, A: TokenProvider>`, on the
  `stack-kms-aws` template. Every encrypt, decrypt and rewrap uses
  `batch_input`, a single key too, so there is one request shape. `wrap` and
  `unwrap` are a batch of one. `generate_wrapped` is the trait default
  (local key, one `wrap`): Transit's `datakey` endpoint has no batch form.
  `batch_limit` is `VaultConfig::batch_size`, default 250
  (`DEFAULT_BATCH_SIZE`). Both key modes. `send_json(method, path, body)` is
  public (tests use it to enable the engine and create keys).
- **Decision:** the associated data. The client **always** encrypts a bound
  key. For a derived key (`derived=true`) it also sends the whole `aad` as
  `context` (base64), so Vault's own derivation binds the keyset id, iv and
  descriptor. Tested on Vault 1.20: a non-derived key **silently ignores**
  `context`, and an unknown parameter only adds a warning, so neither can be
  the binding on its own. `associated_data` (Vault 1.16 and later) is not
  used: on an older Vault or another implementation it would be dropped with
  only a warning. **Alternative:** context only for derived keys and the bound
  key only for the others. **Reason:** one plaintext format for every key,
  and a wrong derivation setting can then fail a call but never weaken the
  binding (a test covers a non-derived key configured as derived).
- **Decision:** how the client knows a key is derived: `KeyDerivation`
  in the config, `Detect` (the default) reads `GET /v1/{mount}/keys/{name}`
  once per key and keeps the answer; `Derived` and `NotDerived` skip the
  read. `Detect` also refuses a missing key (`NotFound`, because Transit's
  `encrypt` would create it when the token has `create`) and a key type that
  is not an AEAD (`aes256-gcm96`, `aes128-gcm96`, `chacha20-poly1305`) or
  cannot encrypt and decrypt (`AccessDenied`). **Alternative:** a flag in the
  keyset record. **Reason:** the record format is CIP-5306's and is shared by
  every vendor; the key read costs one call per key per process.
- **Decision:** the stored wrapped key is `1 ‖ key version (u32 BE) ‖ the
  decoded Vault ciphertext`, not the `vault:vN:base64` text: 98 bytes for a
  bound key, about 40 fewer per value in the leaf tag. `compact_ciphertext`
  and `expand_ciphertext` convert, and refuse anything that does not re-encode
  to the same text. A wrapped key that does not expand is refused as
  `InvalidCiphertext` before any call.
- **Decision:** `key_ref` is the Transit key name: one path segment of
  `[A-Za-z0-9._-]`, not `.` or `..`. Anything else is `NotFound` before any
  call (no path injection). The mount and the namespace are one or more such
  segments; the address must be HTTP or HTTPS with no user, query or
  fragment.
- **Decision:** error mapping (`error_kind(status, message)`): 401 and 403
  `AccessDenied`; 404 `NotFound` (a missing mount or key read); 429
  `Throttled`; 5xx `Unavailable` (503 is sealed or standby); any other 4xx
  `AccessDenied`. A 400 maps by Vault's error text, lower case:
  `NOT_FOUND_MARKERS` (`encryption key not found`, `key not found`) first,
  then `INVALID_CIPHERTEXT_MARKERS` (`invalid ciphertext`, `message
  authentication failed`, `unable to decrypt`, `could not decode`,
  `ciphertext version`, `version is too new`); any other 400 is
  `AccessDenied` (for example a derived key with no context), as for AWS. The
  text is the first failed batch item's `error`, else `errors`. A failed item
  in a 200 batch fails the whole batch. A bound key that does not open is
  `InvalidCiphertext`; a success that cannot be read is `Unavailable`.
- **Decision:** a 403 calls the new `TokenProvider::invalidate` (default:
  nothing), so a cached login token that Vault revoked is dropped and the
  next request logs in again. The failed request is not retried.
- **Decision:** `rewrap(key_ref, wrapped, aad)` is a public method (Transit
  `rewrap`, with `context` for a derived key), not a trait method. It moves a
  wrapped key to the latest key version without the key leaving Vault.
  `KeysetRecord::rewrap` (unwrap and wrap) still works for a move to another
  key.

### Auth

- **Decision:** the seam is `TokenProvider` (future bounded by
  `MaybeSend`, plus `invalidate`). `VaultToken` (wiped, never printed) is the
  static provider (`VAULT_TOKEN`). `AppRoleLogin` (everywhere) and
  `KubernetesLogin` (native only; it reads the service account token file on
  each login) log in at `/v1/auth/{mount}/login` and return the token with
  its lease. A refused login (HTTP 400 or 403) is `AccessDenied`.
- **Decision:** `CachedToken` logs in again before the lease ends: 5 minutes
  before (`DEFAULT_REFRESH_BEFORE_EXPIRY`), or a third of the lease before
  when the lease is shorter. One login at a time; a failed login returns the
  cached token while its lease lasts. A token with no lease is kept until
  `invalidate`. **Alternative:** `renew-self`. **Reason:** a renewal cannot
  pass the token's max TTL, so a client that renews must also log in again;
  one path is simpler and is tested. The docs note that each AppRole login
  uses one use of a `secret_id` with a use limit.
- **Decision:** `DefaultAuth::from_env` (native) picks, in order:
  `VAULT_TOKEN`; `VAULT_APPROLE_ROLE_ID` + `VAULT_APPROLE_SECRET_ID` (mount
  `VAULT_APPROLE_MOUNT`, default `approle`); `VAULT_KUBERNETES_ROLE` (mount
  `VAULT_KUBERNETES_MOUNT`, default `kubernetes`; token file
  `VAULT_KUBERNETES_TOKEN_PATH`, default the service account path). Vault has
  no standard names for the AppRole and Kubernetes variables; these are ours.
  `VaultConfig::from_env` reads `VAULT_ADDR`, `VAULT_NAMESPACE` and
  `VAULT_TRANSIT_MOUNT` (default `transit`). `VaultTransit::from_env`
  (`DefaultVaultTransit`, feature `http`, native) builds both.
- **Not supported:** a custom CA (`VAULT_CACERT`) and mTLS client
  certificates. `HttpVendorTransport` uses the platform verifier. No ticket
  asks for them.

### Tests and CI

- **Decision:** the fixtures were recorded from `vault server -dev` 1.20.4
  by `tests/vault_dev.rs`'s `records_the_fixtures` (it runs only with
  `STACK_KMS_VAULT_RECORD_FIXTURES=1`, against dev root token
  `fixture-root-token`). Each file is an exchange sequence (the key read,
  then the call): encrypt, decrypt, a batch of three each way, all for a
  derived and a non-derived key; rewrap after a rotation; an AppRole login;
  and eight real error responses. Written by hand, and named so: the
  Kubernetes login (a dev server has no Kubernetes) and five errors a dev
  server does not give (429, 503 sealed, 500, a policy 403, a retired key
  version).
- **Decision:** the contract suite runs over an in-process Transit emulator
  (`tests/common::TransitEmulator`: AES-GCM, derived keys that require
  `context` and plain keys that ignore it, as Vault does; the batch and error
  shapes; AppRole and Kubernetes logins; token and namespace checks), for a
  derived and a non-derived key, with `Detect` and with the derivation
  configured, at batch size 4 so the chunking runs.
- **Decision:** `tests/vault_dev.rs` runs when `STACK_KMS_VAULT_ADDR` is set
  (token `STACK_KMS_VAULT_TOKEN`, default `root`): the whole contract suite
  for a derived and a non-derived key, eight error mappings, rotation and
  rewrap, and an AppRole login with a least-privilege policy. It ran locally
  against `hashicorp/vault:1.20` in Docker and passed.
- **Decision:** CI: a new `vault` job in `tests-crates.yml` runs
  `hashicorp/vault:1.20` (pinned by the multi-platform index digest) in dev
  mode as a service and calls the new mise task
  `test:vault:stack-kms-vault`, which refuses to run without the address. A
  new `doc:stack-kms-vault` task joins `mise run doc`. `wasm:wasi-check` now
  checks `stack-kms-vault` (default features). `tests-crates.yml` and
  `udeps.yml` include the new path; `crates-ci.test.mjs` now expects eight
  crate task files.
- **Decision:** `stack-kms-vault` joins the `stack-kms-vendor` release group,
  staged (`release = false`, `publish = false` in `release-plz.toml`), and
  the `cargo publish --dry-run` list. Arming it follows the CIP-5307 steps,
  with `cargo publish -p stack-kms-vault` after `stack-kms-vendor`. No
  changeset: Rust only.
- **Note:** a local `cargo publish --dry-run` can fail with "no `bound` in
  `stack_kms_vendor`" after an earlier dry run packaged an older
  `stack-kms-vendor` 0.1.0: cargo treats the packaged crate as an immutable
  registry crate and reuses its old build. Remove
  `~/.cargo/registry/src/-*/stack-kms-vendor-0.1.0`, `target/package` and the
  `stack-kms-vendor` files in `target/debug/{.fingerprint,deps}`. CI starts
  clean.
- **Note:** `scripts` vitest still has the two failures noted in CIP-5306;
  every other file passes.

### Deferred

- **Deferred to CIP-5309:** Azure Key Vault RSA wrap binds its associated
  data with `stack_kms_vendor::bound`.
- **Deferred to CIP-5311:** the guest wiring: `VaultTransit::new(config,
  HostVendorTransport, <a TokenProvider over the host import>)`, and the
  status mapping of the new errors.
- **Deferred to CIP-5312:** `stash keyset` can create Vault records with
  `VaultTransit::from_env()`.
- **Deferred (no ticket):** `VAULT_CACERT` and mTLS; `renew-self`.

## Orchestrator review of CIP-5310

- **Revisit:** Vault with a private CA (`VAULT_CACERT`) and mTLS client
  certificates is not supported. Many self-hosted Vault deployments use a
  private CA, so this is likely the first customer request. It is a follow-up,
  not part of CIP-5310.

## CIP-5308: Google Cloud KMS key vendor backend (stack-kms-gcp)

### The Cloud KMS client

- **Decision:** `stack-kms-gcp` is a new root workspace member with
  `GcpKms<T: VendorTransport, A: TokenProvider>`, on the `stack-kms-vault`
  template. `wrap` is `cryptoKeys.encrypt`, `unwrap` is `cryptoKeys.decrypt`
  (REST v1, JSON, standard base64). `generate_wrapped`, `batch_limit`,
  `wrap_batch` and `unwrap_batch` are the trait defaults: Cloud KMS has no
  data key generation and no batch operation, so each wrapped data key is a
  key from the CSPRNG and one `encrypt`, and the adapter runs the calls
  through `run_batch` (concurrency 16). Both key modes. `send_json(method,
  path, body)` is public, as for the other vendors.
- **Decision:** `key_ref` is the crypto key name
  (`projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`). A
  `…/cryptoKeyVersions/{n}` name is accepted too and pins `encrypt` to that
  version; `decrypt` always names the crypto key (Cloud KMS requires that).
  `parse_key_name` checks the shape: each id is `[A-Za-z0-9._-]`, not `.` or
  `..`; only the project id may hold `:` (a domain-scoped project). Anything
  else is `NotFound` before any call, so a key reference cannot add a method
  (`:decrypt`) or change the path. **Alternative:** a version path as the
  only form (the trait docs said so). **Reason:** the crypto key name keeps
  rotation transparent; the trait docs now say "crypto key name".
- **Decision:** the stored wrapped key is `1 ‖ key version (u32 BE) ‖ Cloud
  KMS ciphertext`, the same layout as Vault's. The version comes from the
  `encrypt` response `name`, which must be a version of the requested key,
  else the response is refused (`Unavailable`). `wrapped_key_version` reads
  it. **Alternative:** store the ciphertext alone (Cloud KMS finds the
  version from the ciphertext). **Reason:** the ticket asks to record the
  version; 5 bytes per value lets an operator find which versions stored
  keys still need before a version is disabled or destroyed, which makes
  its ciphertexts unrecoverable.
- **Decision:** the associated data is sent whole as
  `additionalAuthenticatedData`: it holds the keyset id and, for a wrapped
  data key, the iv and the descriptor, as the AWS crate binds all of `aad`.
  No `stack_kms_vendor::bound`: Cloud KMS AAD is native and authenticated.
  There are no readable fields, because Cloud KMS does not show the AAD in
  audit logs or IAM conditions.
- **Decision:** CRC32C is used on every call (in-crate, table-driven,
  `stack_kms_gcp::crc32c`, RFC 3720 vectors pinned). Encrypt sends
  `plaintextCrc32c` and `additionalAuthenticatedDataCrc32c` and requires
  `verifiedPlaintextCrc32c`, `verifiedAdditionalAuthenticatedDataCrc32c`
  and a matching `ciphertextCrc32c`. Decrypt sends `ciphertextCrc32c` and
  `additionalAuthenticatedDataCrc32c` and requires a matching
  `plaintextCrc32c`. A missing or wrong check is `Unavailable`. The int64
  fields are sent as strings and read as a string or a number.
  **Reason:** about 40 lines, no new dependency, and it is Google's
  recommended practice. No CRC32C crate was in the lockfile (`crc32fast` is
  CRC-32/IEEE).
- **Decision:** error mapping (`error_kind(http status, google.rpc code,
  message)`), by `error.status` first: `PERMISSION_DENIED`, `UNAUTHENTICATED`
  to `AccessDenied`; `NOT_FOUND` to `NotFound`; `RESOURCE_EXHAUSTED` to
  `Throttled`; `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `INTERNAL`, `UNKNOWN`,
  `ABORTED`, `CANCELLED` and `FAILED_PRECONDITION` (a disabled or destroyed
  version, as AWS `DisabledException`) to `Unavailable`. `INVALID_ARGUMENT`
  maps by its message, lower case: `CHECKSUM_MARKERS` (`checksum`,
  `crc32c`) first to `Unavailable` (damaged in transit), then
  `INVALID_CIPHERTEXT_MARKERS` (`decryption failed`, `ciphertext is
  invalid`) to `InvalidCiphertext`, else `AccessDenied`. No code: the HTTP
  status, with any other 4xx `AccessDenied` (the CIP-5307 rule). The
  markers apply to any operation, not only `decrypt`: an `encrypt` never
  says "Decryption failed", so the extra check bought nothing. A 401 calls
  `TokenProvider::invalidate`. A plaintext that is not 32 bytes is
  `InvalidCiphertext`.
- **Note:** Cloud KMS answers `PERMISSION_DENIED`, not `NOT_FOUND`, for a key
  the caller may not see. So a missing key is often `AccessDenied`. The live
  test accepts either.
- **Decision:** the endpoint is `GcpKmsConfig::with_endpoint` (default
  `https://cloudkms.googleapis.com`; any HTTP or HTTPS origin with no path),
  for regional endpoints and tests. No environment variable: the Google SDKs
  have no common name for it. No `x-goog-user-project` (quota project)
  header: a service account key does not need one. Add it if a customer
  asks.

### Credentials

- **Decision:** the seam is `TokenProvider` (future bounded by `MaybeSend`,
  plus `invalidate`), with `AccessToken` (wiped, never printed) as the
  static provider, `CachedToken` (5 minutes before expiry, or a third of the
  life when shorter; one fetch at a time; a failed fetch keeps an unexpired
  token), all on the Vault template.
- **Decision:** `ServiceAccountKey::from_json(bytes)` (everywhere) and
  `from_file(path)` (native) read a key file. It refuses any `type` but
  `service_account` (so `authorized_user` and `external_account` files fail
  with a clear message), a key that is not RSA PKCS #8 PEM, and a
  `token_uri` that is not HTTPS (default `https://oauth2.googleapis.com/token`).
  `ServiceAccountLogin` signs `{"alg":"RS256","kid":…,"typ":"JWT"}` and
  `{"iss","scope","aud":token_uri,"iat","exp":iat+3600}` and posts the RFC
  7523 form to `token_uri`. The scope is `https://www.googleapis.com/auth/cloudkms`
  (`with_scope` changes it). **Alternative:** a self-signed JWT sent
  directly as the bearer token (no exchange). **Reason:** the ticket names
  the exchange, and it works for every key the token endpoint accepts.
- **Decision (RSA crate):** RS256 uses the `rsa` crate 0.9.10 (RustCrypto,
  pure Rust; already in `packages/eql/Cargo.lock`), with `rand_core` 0.6
  `OsRng` (getrandom 0.2, already in the root lockfile) as the blinding RNG.
  It builds for wasm32-wasip1 (checked by `wasm:wasi-check`). **Alternatives:**
  `ring` (in the root lockfile through jsonwebtoken, but it needs a C
  toolchain with a wasm32 target, and stack-auth keeps it off wasm32 for
  that reason); `aws-lc-rs` (does not build for wasm32); `jsonwebtoken`
  (pulls ring or aws-lc-rs). **Known issue:** RUSTSEC-2023-0071 (the Marvin
  timing attack: the private key operation is not constant time) has no
  fixed `rsa` release. The risk here is low: the key signs one JWT per hour
  on the client, the signature uses blinding (`try_sign_with_rng`), and an
  attacker must time those signatures over the network. OSV-Scanner
  (`fail-on-vuln: false`) will report it as an alert, as it already does
  for the EQL lockfile. Revisit when `rsa` 0.10 is stable.
- **Decision:** `MetadataServerLogin` (native only, `cfg(not(target_arch =
  "wasm32"))`) gets `http://{host}/computeMetadata/v1/instance/service-accounts/default/token`
  with `Metadata-Flavor: Google`. The host is `metadata.google.internal`, or
  `GCE_METADATA_HOST` (the Google SDK name), checked as `host[:port]` so it
  cannot change the path. A 404 from it (no service account) is
  `AccessDenied`.
- **Decision:** `DefaultCredentials::from_env` (native) picks, in order:
  `GOOGLE_OAUTH_ACCESS_TOKEN` (a static token, the name Terraform's Google
  provider uses; handy with `gcloud auth print-access-token`);
  `GOOGLE_APPLICATION_CREDENTIALS` (a service account key file); else the
  metadata server. `GcpKms::from_env` (`DefaultGcpKms`, feature `http`,
  native) builds it, with a 1 s connect limit on the credentials transport
  so the metadata probe fails fast off Google Cloud. **Not supported:**
  `authorized_user` files (`gcloud auth application-default login`),
  `external_account` files (workload identity federation) and service
  account impersonation. No ticket asks for them.

### Tests and CI

- **Decision:** no fixture was recorded from Google Cloud (no emulator and
  no credentials here). The responses are written by hand in the documented
  Cloud KMS and OAuth shapes. The request sides were computed by a separate
  Python script, not by the client (base64, CRC32C, the AAD frame, the form
  body), and the client produced the same bytes on the first run. Fixtures:
  encrypt, decrypt, an encrypt pinned to a version, a decrypt under an old
  version, the service account token exchange, the metadata server token,
  and 13 error responses.
- **Decision:** the JWT known-answer test signs with a TEST-ONLY 2048-bit RSA
  key generated for these tests (`openssl genpkey`). The expected JWT
  (`tests/fixtures/test_only_jwt_assertion.txt`) was signed by `openssl dgst
  -sha256 -sign`, a second implementation, and the crate's output matches it
  byte for byte. The key is stored as base64 PKCS #8 DER
  (`test_only_rsa_key.pkcs8.b64`), and the service account JSON is built at
  run time, so no file holds a PEM block or a key file that push protection
  could take for a leaked Google key. The fixture tokens are
  `fixture-*-token`, not `ya29.`.
- **Decision:** the contract suite runs over an in-process emulator
  (`tests/common::KmsEmulator`: AES-256-GCM with the AAD bound, versions and
  rotation, the CRC32C checks, Google's error shapes, a token endpoint that
  verifies the JWT signature with the test key, and the metadata server),
  with a static token and with service account credentials.
- **Decision:** `tests/live.rs` runs when `STACK_KMS_GCP_LIVE_KEY` is set
  (credentials from `DefaultCredentials`): the whole contract suite, and
  wrong AAD, a damaged ciphertext and a missing key. **It has not run**:
  there are no Google Cloud credentials here. The new mise task
  `test:live:stack-kms-gcp` refuses to run without the key and credentials.
- **Decision:** CI: a new workflow, `integration-gcp-kms.yml` (push to main
  and pull requests on the crate paths, plus `workflow_dispatch`), with one
  job, `live`. Its condition is `vars.STACK_KMS_GCP_LIVE_KEY != '' &&` the
  canonical fork-PR clause, so it is **inert until the variable is set** and
  then fails loudly if the secret is empty (a shell pre-flight first, as
  `require-cs-secrets` does; that action and `ffi-binding-step-order.test.mjs`
  are for `CS_*` credentials and do not apply). **Alternative:** a job in
  `tests-crates.yml`, or a fork-guarded job with no variable. **Reason:**
  without the variable, every PR on the crate would go red until someone
  sets up Google Cloud. `workflow-dispatch-job-conditions.test.mjs` now
  lists the workflow and the job and holds the variable open;
  `crates-ci.test.mjs` names it as the sole caller of the live task.
- **To turn the live job on (a person):** create a symmetric
  `ENCRYPT_DECRYPT` crypto key for the test only; a service account with
  `roles/cloudkms.cryptoKeyEncrypterDecrypter` on that key only, and a JSON
  key for it. Then set:
  - repository **variable** `STACK_KMS_GCP_LIVE_KEY` = the crypto key name;
  - repository **secret** `STACK_KMS_GCP_SERVICE_ACCOUNT_KEY` = the JSON key.
- **Decision:** `tests-crates.yml` and `udeps.yml` include the new path,
  `cargo publish --dry-run` packages the crate (passed locally),
  `wasm:wasi-check` checks it (passed), and `doc:stack-kms-gcp` joins `mise
  run doc`. `crates-ci.test.mjs` now expects nine crate task files.
- **Decision:** `stack-kms-gcp` joins the `stack-kms-vendor` release group,
  staged (`release = false`, `publish = false`). Arming it follows the
  CIP-5307 steps, with `cargo publish -p stack-kms-gcp` after
  `stack-kms-vendor`. No changeset: Rust only.
- **Note:** `scripts` vitest still has the two failures noted in CIP-5306
  (`bench-index-expressions`, `check-auth-npm-changeset`); every other file
  passes.

### Deferred

- **Deferred to CIP-5311:** the guest wiring: `GcpKms::new(GcpKmsConfig::new(),
  HostVendorTransport, <a TokenProvider over the host import>)`, and the
  status mapping. `ServiceAccountLogin` also works in the guest if the host
  passes key bytes, but ADR-0011 says the host supplies the token.
- **Deferred to CIP-5312:** `stash keyset` can create Cloud KMS records with
  `GcpKms::from_env()`.
- **Deferred (no ticket):** `authorized_user` and `external_account`
  credentials, impersonation, a quota project header, and re-recording the
  fixtures from real Cloud KMS once the live job has credentials.

## Orchestrator review of CIP-5308

- **Revisit (security):** `stack-kms-gcp` signs its OAuth JWT with the `rsa`
  crate, which has the open advisory RUSTSEC-2023-0071 (Marvin, a timing side
  channel). The key it uses is the customer's service account key. Accepted
  for now with the agent's reasoning, but a security reviewer must sign it off
  before the crate is armed for release. One option: in the Go guest, ask the
  host for an access token, not for the service account key, so that the guest
  never signs (CIP-5311).
- **Not verified:** the GCP fixtures are hand-written from the documented
  shapes, not recorded from Cloud KMS. The opt-in live job is the only real
  check. It needs the variable `STACK_KMS_GCP_LIVE_KEY` and the secret
  `STACK_KMS_GCP_SERVICE_ACCOUNT_KEY`.

## CIP-5309: Azure Key Vault key vendor backend (stack-kms-azure)

### The Key Vault client

- **Decision:** `stack-kms-azure` is a new root workspace member with
  `AzureKeyVault<T: VendorTransport, A: TokenProvider>`, on the
  `stack-kms-gcp` template. `wrap` is `POST {key}/{version}/wrapkey`,
  `unwrap` is `POST {key}/{version}/unwrapkey` (JSON, base64url).
  `generate_wrapped`, `batch_limit`, `wrap_batch` and `unwrap_batch` are the
  trait defaults: Key Vault has no data key generation and no batch
  operation. Both key modes. `send_json(method, key_ref, operation, body)` is
  public, as for the other vendors. Key Vault and Managed HSM are one client:
  the host of the key identifier selects the token scope.
- **Decision:** the API version is **7.4** (`API_VERSION`). **Alternative:**
  7.5 or 7.6. **Reason:** 7.4 is GA on Key Vault and Managed HSM and has every
  operation the client uses; nothing newer is needed.
- **Decision:** `key_ref` is the key identifier,
  `https://{vault}.vault.azure.net/keys/{name}` or
  `https://{hsm}.managedhsm.azure.net/keys/{name}`, optionally `/{version}`.
  `KeyId::parse` accepts only the six known Azure DNS suffixes (public, China
  and US Government clouds, Key Vault and Managed HSM), HTTPS, no port, query,
  fragment or credentials, names `[A-Za-z0-9-]` and versions `[A-Za-z0-9]{1,64}`.
  Anything else is `NotFound` before any call. **Alternative:** any HTTPS host,
  or a configurable endpoint. **Reason:** the client sends a bearer token to
  that host, so an edited keyset record must not be able to send it elsewhere.
  Private endpoints keep the public DNS names, so the list covers them. No
  test needs another host: the emulator answers any URL.
- **Decision:** the algorithm follows the key type: `RSA` and `RSA-HSM` wrap
  with **RSA-OAEP-256**, `oct` and `oct-HSM` with **A256KW**; `EC` and other
  types are refused (`AccessDenied`). The client learns the type and, for an
  unversioned key identifier, the current version from one
  `GET /keys/{name}[/{version}]`, kept per key reference for the life of the
  client. `AzureKeyVaultConfig::with_algorithm` fixes the algorithm; with a
  versioned key identifier the client then reads no key. A key whose type
  does not match the configured algorithm is refused. **Alternative:** read
  the key on every wrap, or a TTL on the cached version. **Reason:** the
  ticket says "resolve once"; one read per key per process is cheap. To keep
  a disabled version from blocking wraps, a failed wrap drops the cached
  version, so the next wrap reads the key again (tested).
- **Decision (the stored wrapped key):** `1 ‖ algorithm(1: 1 = RSA-OAEP-256,
  2 = A256KW) ‖ version length(1) ‖ version (ASCII) ‖ Azure ciphertext`
  (`compact_ciphertext`, `split_wrapped_key`, `wrapped_key_version`). It is
  the Vault/GCP layout with the version as a string id (Azure versions are 32
  hexadecimal characters) and with the algorithm added. An unwrap therefore
  needs no key read and no configuration: the record key and every wrapped
  data key name the version and algorithm that made them. The keyset record's
  `key_ref` can stay unversioned (rotation needs no record change); a
  versioned one pins wraps only. Size: 115 bytes for A256KW, 291 bytes for
  RSA-OAEP-256 with a 2048-bit key. **Alternative:** store the full versioned
  `kid` (60 to 100 bytes more per value, and it repeats the key reference).
- **Decision (no AAD):** the client **always** wraps the bound key of
  `stack_kms_vendor::bound` (CIP-5310), padded with 7 zero bytes to **72
  bytes** (`WRAP_PLAINTEXT_LEN`), for both algorithms. An unwrap refuses a
  plaintext that is not 72 bytes, has non-zero padding, or whose digest does
  not match (`InvalidCiphertext`). **Reason:** A256KW (RFC 3394) needs a
  multiple of 8 bytes and at least 16; the bound key is 65. RSA-OAEP-256 with
  a 2048-bit key takes up to 190 bytes, so 72 fits too, and one plaintext
  format serves both. **Alternative:** pad only for A256KW. **Reason:** one
  format is simpler and has one test. Both algorithms are non-malleable
  (RSA-OAEP; AES key wrap has its own integrity check), which the bound key
  needs. **The Azure trade-off** (documented on `AzureKeyVault`): Azure does
  not see or log the binding, so a wrapped key moved to another keyset, value
  or descriptor unwraps at Azure and is then refused by the client. The
  leaf AAD binds the descriptor as for every vendor.
- **Decision:** error mapping (`error_kind(status, codes, unwrap)`), where
  `codes` are `error.code` and `error.innererror.code`: `KeyDisabled`,
  `KeyExpired`, `KeyNotYetValid` to `Unavailable` (as AWS
  `DisabledException`); 429 or `Throttled` to `Throttled`; 401, 403,
  `Unauthorized`, `Forbidden` to `AccessDenied`; 404, `KeyNotFound`,
  `NotFound` to `NotFound`; 5xx to `Unavailable`; 400 `BadParameter` **on an
  unwrap** to `InvalidCiphertext` (Azure could not decrypt: damaged bytes, or
  another key or version); any other 4xx to `AccessDenied` (the CIP-5307
  rule). A 401 calls `TokenProvider::invalidate`. A wrap response whose `kid`
  is not exactly the requested key version, or with no base64url value, is
  `Unavailable`. **Known limit:** a `BadParameter` on an unwrap for another
  reason (for example a refused API version) also reads as
  `InvalidCiphertext`; Azure gives no finer code.
- **Decision (Retry-After):** on a 429 the client sleeps the `Retry-After`
  seconds (through the transport, at most `MAX_RETRY_AFTER` = 30 s; an HTTP
  date is ignored), then returns `Throttled`, and the adapter's backoff
  retries. **Alternative:** retry inside the client. **Reason:** the adapter
  owns the retry policy; the client only honours the server's wait. A 503
  with `Retry-After` does not wait: `Unavailable` is not retried.
- **Decision:** no `rsa` dependency in the crate. Azure does every RSA
  operation. The `rsa` crate is a **dev-dependency only**, for the fixture
  emulator's RSA-OAEP-256, so RUSTSEC-2023-0071 (see the orchestrator review
  of CIP-5308) does not reach the shipped crate. `aes` 0.8.4 (already in the
  lockfile) is a dev-dependency for the emulator's RFC 3394 key wrap.

### Credentials

- **Decision:** the seam is `TokenProvider::token(scope)`: the scope is an
  argument, because one client can reach Key Vault
  (`https://vault.azure.net/.default`) and Managed HSM
  (`https://managedhsm.azure.net/.default`), and national clouds have their
  own. `CachedToken` keeps one token per scope (same refresh rules as GCP and
  Vault); `invalidate` drops all. `AccessToken` (wiped, never printed) is the
  static provider and is used for every scope; it is the guest seam
  (ADR-0011).
- **Decision:** `ClientSecretLogin` (everywhere) posts the client credentials
  grant to `{authority}/{tenant}/oauth2/v2.0/token`. The tenant must be
  `[A-Za-z0-9.-]` (it is in the path). `AZURE_AUTHORITY_HOST` (the Azure SDK
  name) changes the host and must be HTTPS with no path.
- **Decision:** `WorkloadIdentityLogin` (native only) posts the federated
  token from `AZURE_FEDERATED_TOKEN_FILE` as a `client_assertion`, read on
  each login. It was cheap: the same request as the client secret.
- **Decision:** `ManagedIdentityLogin` (native only): IMDS
  (`GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=…`,
  `Metadata: true`) or App Service (`IDENTITY_ENDPOINT` +
  `X-IDENTITY-HEADER`, api-version 2019-08-01). `AZURE_CLIENT_ID` names a
  user-assigned identity (`client_id`). `IDENTITY_ENDPOINT` must be HTTP to a
  loopback host or HTTPS, with no query, so the identity header cannot go
  elsewhere. A token's life is `expires_in` (number or string), else
  `expires_on` less now. IMDS 410 (updating) is `Unavailable`; a refused
  identity (400, 404) is `AccessDenied`.
- **Decision:** `DefaultCredentials::from_env` (native) picks, in the
  `DefaultAzureCredential` order: `AZURE_KEY_VAULT_ACCESS_TOKEN` (a static
  token; the name is ours, Azure has none); `AZURE_TENANT_ID` +
  `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`; `AZURE_TENANT_ID` +
  `AZURE_CLIENT_ID` + `AZURE_FEDERATED_TOKEN_FILE`; else managed identity
  (App Service when `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` are set, else
  IMDS). `AzureKeyVault::from_env` (`DefaultAzureKeyVault`, feature `http`,
  native) builds it with a 1 s connect limit on the credentials transport.
- **Decision (deferred, security):** **client certificate credentials are not
  supported**. They sign a JWT with the service principal's RSA key, which
  would put the `rsa` crate (RUSTSEC-2023-0071) back into a shipped crate.
  `AZURE_CLIENT_CERTIFICATE_PATH` without a secret is refused with a clear
  message. Also not supported: Azure CLI credentials, Azure Arc and Service
  Fabric managed identity.

### Tests and CI

- **Decision:** no fixture was recorded from Azure (no emulator and no
  credentials here). Responses are written by hand in the documented Key
  Vault, Entra ID and managed identity shapes. The request sides were
  computed by a separate Python script, not by the client (base64url, the AAD
  frame, the bound key digest and padding, the form bodies); the client sent
  the same bytes on the first run. RSA-OAEP-256 ciphertexts were made by
  `openssl pkeyutl` under a **TEST-ONLY 2048-bit RSA key** generated for these
  tests (`tests/fixtures/test_only_rsa_key.pkcs8.b64`, base64 PKCS #8 DER, no
  PEM block); A256KW ciphertexts by a Python RFC 3394 key wrap over `openssl
  enc -aes-256-ecb`, under the RFC 3394 example key (`TEST_ONLY_KEK`), checked
  against RFC 3394 §4.6. A test opens each fixture ciphertext with the
  test-only keys. Fixtures: wrap (with the key read) and unwrap for a Key
  Vault RSA key and a Managed HSM `oct-HSM` key, a pinned older version,
  client secret, workload identity, IMDS and App Service tokens, and 14 error
  responses. Tokens and secrets are `fixture-*`; no real-shaped secret.
- **Decision:** the contract suite runs over an in-process emulator
  (`tests/common::KeyVaultEmulator`: RSA-OAEP-256 with the test-only key (every
  RSA version uses it), A256KW with an AES key per version, rotation,
  disabled versions, throttles with `Retry-After`, Azure's error shapes, and a
  token endpoint whose tokens carry a scope that each key request checks),
  for an RSA key and an `oct-HSM` key, with a static token and with client
  secret credentials.
- **Decision:** `tests/live.rs` runs when `STACK_KMS_AZURE_LIVE_KEY` (a Key
  Vault RSA key) is set, and also tests `STACK_KMS_AZURE_LIVE_HSM_KEY` when
  set: the whole contract suite, wrong AAD, a damaged ciphertext and a
  missing key. **It has not run**: no Azure credentials here. The mise task
  `test:live:stack-kms-azure` refuses to run without the key and credentials.
- **Decision:** CI: `integration-azure-key-vault.yml`, one job `live`, on
  the GCP template: inert until the variable is set, then a pre-flight fails
  the job if a secret is empty; the secrets reach only the test step.
- **To turn the live job on (a person):** create an RSA key (2048 bits or
  more) in a Key Vault for the test only (optionally an `oct-HSM` AES-256 key
  in a Managed HSM); an app registration with a client secret and the role
  "Key Vault Crypto Service Encryption User" on that key only ("Managed HSM
  Crypto Service Encryption User" on the HSM key). Then set:
  - repository **variable** `STACK_KMS_AZURE_LIVE_KEY` = the key identifier;
  - optional repository **variable** `STACK_KMS_AZURE_LIVE_HSM_KEY`;
  - repository **secrets** `STACK_KMS_AZURE_TENANT_ID`,
    `STACK_KMS_AZURE_CLIENT_ID`, `STACK_KMS_AZURE_CLIENT_SECRET`.
- **Decision:** `tests-crates.yml` and `udeps.yml` include the new path,
  `cargo publish --dry-run` packages the crate (passed locally with the CI
  list), `wasm:wasi-check` checks it (passed), `doc:stack-kms-azure` joins
  `mise run doc`, and `crates-ci.test.mjs` expects ten crate task files.
  `workflow-dispatch-job-conditions.test.mjs` lists the workflow and job.
- **Decision:** `stack-kms-azure` joins the `stack-kms-vendor` release group,
  staged (`release = false`, `publish = false`). Arming it follows the
  CIP-5307 steps, with `cargo publish -p stack-kms-azure` after
  `stack-kms-vendor`. No changeset: Rust only.
- **Note:** `scripts` vitest still has the two failures noted in CIP-5306
  (`bench-index-expressions`, `check-auth-npm-changeset`); every other file
  passes.

### Deferred

- **Deferred to CIP-5311:** the guest wiring: `AzureKeyVault::new(config,
  HostVendorTransport, <a TokenProvider over the host import>)`. The host
  import must take the scope (Key Vault and Managed HSM need different
  tokens). Status mapping of the new errors.
- **Deferred to CIP-5312:** `stash keyset` can create Azure records with
  `AzureKeyVault::from_env()`.
- **Deferred (no ticket):** client certificate credentials (blocked on a
  constant-time RSA signer), Azure CLI and Arc credentials, re-recording the
  fixtures from real Azure once the live job has credentials.

## CIP-5311: Go SDK: key vendor backends through the encrypt guest

### Guest size (measured)

- **Measurement** (release builds, `mise run wasm:guest:build` and
  `wasm:guest:build:eql`, on this branch before and after):

  | build | before | after | growth |
  |---|---|---|---|
  | `stack_encrypt_guest.wasm` (no EQL types) | 1,543,167 B | 1,906,377 B | +363,210 B (+23.5%) |
  | `stack_encrypt_guest_eql.wasm` | 1,598,896 B | 1,965,401 B | +366,505 B (+22.9%) |
  | deterministic test build | n/a | 1,657,639 B | |
  | deterministic test build, EQL | n/a | 1,726,501 B | |

  **Decision:** ship one guest with all five backends, as ADR-0011 says.
  The growth is below the 30% limit the orchestrator set. **Alternative:**
  one guest per vendor. **Reason:** it would multiply the embedded files,
  the test builds and the release workflow.

### The credential import

- **Decision (binding, from the orchestrator):** the host supplies
  ready-to-use short-lived credentials, never a long-lived signing key: AWS
  temporary credentials, a Google OAuth access token, an Azure access token
  for the scope the guest asks for, a Vault client token. The guest does no
  RSA and reads no service account key.
- **Decision:** one import, `cipherstash_transport::vendor_credential_get(
  vendor: u32, scope_ptr, scope_len, cred_ptr_out, cred_len_out) -> i32`,
  the shape of `token_get`. `vendor` is the `KeyVendor` byte; `scope` is the
  OAuth scope for Google Cloud and Azure and empty for AWS and Vault. The
  credential is one value in the transport codec: an object of strings
  (`access_key_id`, `secret_access_key`, optional `session_token` for AWS;
  `token` for the others) and an optional `expires_at` (`i64`, Unix
  seconds). **Alternative:** one import per credential kind; JSON.
  **Reason:** one import keeps the surface small; the codec is the format
  every other input uses, and its strings are wiped on drop.
- **Decision:** the guest asks before **each** vendor request and keeps no
  credential between requests. `TokenProvider::invalidate` therefore has
  nothing to drop in the guest, and the import has no "refresh" flag. The
  host's credential chain (the AWS SDK cache, `oauth2.ReuseTokenSource`,
  azidentity) decides when to refresh. **Alternative:** cache in the guest
  with `CachedToken`/`CachedCredentials` and forward `invalidate` to the
  host. **Reason:** credentials live in guest memory only for one request,
  and the Go chains already cache.
- **Decision:** the guest refuses a credential whose `expires_at` has passed,
  a credential with an unknown key, an empty or missing field, or a field
  with a control character (`AccessDenied`, so `ErrForbidden`). A non-zero
  import status is `Unavailable` (`ErrTransport`), the same status as a
  failed `token_get`. The Go host attaches the source's own error to the
  call's error, as it does for the token source, so `errors.Is` matches it.
  **No new status codes:** the vendor failure kinds already map to the
  ZeroKMS statuses (CIP-5304), and the `Diagnostic` code
  `stack_kms::backend` with its `vendor` field tells them apart.
- **Decision:** `stack-kms-gcp` gets a default feature `service-account`
  (the RS256 JWT login and the `rsa` and `rand_core` dependencies); `http`
  implies it. The guest builds the crate with no default features, so the
  `rsa` crate (RUSTSEC-2023-0071) is not in the guest's `Cargo.lock` at all.
  `CLOUD_KMS_SCOPE` moved to `auth` so it stays without the feature.
  `wasm:wasi-check` checks the crate without default features too.
  **Alternative:** rely on LTO to drop the unused RSA code. **Reason:** the
  lockfile, and so OSV, would still carry the advisory.

### The guest

- **Decision:** the cipher's key source is always
  `KeyRouter<ZeroKMS, GuestVendor>` (in the deterministic build,
  `KeyRouter<DeterministicSource, GuestVendor>`). `GuestVendor<T, C>` is one
  enum over the four vendor clients and `StaticKeyVendor`, plus `None`: with
  no backend configured it holds no keyset record, so the router sends
  every request to ZeroKMS and the zero-value client behaves as before.
  **Alternative:** an enum over two cipher types, or an enum key source
  that forwards every `DataKeySource`/`IndexKeySource` method. **Reason:**
  `KeyRouter` already forwards all the provided methods correctly; a second
  forwarder is where one would be forgotten. `GuestVendor::None` answers
  `vendor()` with `Static`; it is never asked (it has no keyset).
- **Decision:** the vendor is configured in the `se_cipher_init` config
  object: `key_vendor` (the `KeyVendor::name()`), `keyset_records` (an array
  of record texts, required, not empty), and per vendor `aws_region`,
  `aws_endpoint`, `vault_address`, `vault_namespace`, `vault_mount`,
  `gcp_endpoint`, `static_key_ref`, `static_key` (32 bytes, a bytes value).
  A key for another vendor than `key_vendor` is refused
  (`ConfigError::NotForVendor`), as an unknown key is. No credential is in
  the config. Azure needs no setting: the key identifier names the vault.
  A refused record keeps its `RecordError` for `se_last_error` and is
  `STATUS_ENCODING` (a `RecordError::Kms` keeps its key status).
- **Decision:** NewClient makes no vendor call: records are parsed and
  checked at `se_cipher_init`, and a record key is unwrapped on the first
  use of its keyset. **Reason:** the ZeroKMS default keyset is the only
  load at init today; a vendor outage then fails the vendor keyset, not the
  whole client.
- **Decision:** the deterministic test build keeps the vendor clients, so it
  now imports `transport_send` and `vendor_credential_get` (not
  `token_get`). Its config is the bare 32-byte seed, as before, or an object
  `{"seed", key_vendor, keyset_records, ...}`. The mise import gates of all
  four builds now require `vendor_credential_get`.
- **Decision:** the vendor client error types (`AwsKmsError`,
  `CredentialsError`, `VaultError`, the three `AuthError`s, `GcpKmsError`,
  `AzureKeyVaultError`, `TransportError`, `RecordError`) are causes whose
  text the guest vouches for in `se_last_error`. **Reason:** each vendor
  crate builds its messages from fixed text, the operation, the HTTP status
  and the vendor's code and message, and never from a key or a secret.

### The Go host

- **Decision (dependency policy):** the module imports **no vendor SDK**.
  The module already depends on `golang.org/x/oauth2` (for
  `auth.OAuth2TokenSource`), and nothing else of a vendor. The credential
  seam is two small interfaces with function adapters:
  `AWSCredentialSource` (`AWSCredentialsFunc`) and `AccessTokenSource`
  (`AccessTokenFunc`, `OAuth2AccessTokens(oauth2.TokenSource)`,
  `StaticAccessToken`), plus `AWSCredentialsFromEnv`. The doc comments show
  the three-line glue for aws-sdk-go-v2, azidentity and the Vault API
  client. **Alternatives:** the vendor SDKs in the core module (four large
  dependency trees for every user); a sub-package or sub-module per vendor
  (`encrypt/vendor/aws`). **Reason:** sub-packages still add the SDKs to the
  one `go.mod` every user downloads the requirements of, and sub-modules
  need their own tags in `release-golang.yml`. The glue is short and is the
  user's own choice of chain. Revisit if users ask for ready-made adapters;
  then make them separate modules.
- **Decision:** the public surface is `WithKeyVendor(KeyVendor)`,
  `WithKeysetRecords(...string)`, a sealed `KeyVendor` interface with five
  struct types (`AWSKMS`, `GoogleCloudKMS`, `AzureKeyVault`, `VaultTransit`,
  `StaticKey`), the credential types `AWSCredentials` and `AccessToken`
  (both hide their secrets from `%v`, `%#v` and slog) and
  `ErrNoKeyVendorCredentials`. Struct literals, not functional options,
  because each backend has two to four settings.
- **Decision:** the options are checked host-side before anything is
  resolved (Go principle 1, the earliest stage): records without a vendor,
  a vendor without records, a missing region, address or credential
  source, and a static key that is not 32 bytes are `ErrEncoding`. The
  guest checks the records themselves at NewClient.
- **Decision:** `StaticKey.Key` is consumed like the client key: NewClient
  wipes it whatever the outcome, a refused config and a replaced option
  included.
- **Decision:** `ErrForbidden`, `ErrNotFound`, `ErrTransport` and
  `ErrAuthentication` keep their names and now document their key vendor
  meaning. **Alternative:** new `ErrKeyVendor*` sentinels. **Reason:** a
  caller branches on the kind, not the backend; the `Diagnostic` names the
  backend.

### Tests

- Guest (native): config parsing of every vendor and every refusal, the
  credential readers (expiry, missing and unknown keys, control characters,
  no secret in a message), the token providers' vendor and scope, an AWS
  request signed with the host credentials, and record refusals. `mise run
  wasm:guest:test`: 76 passed; clippy clean on all four feature sets, native
  and wasm32.
- Go (hermetic, over the deterministic build): a static key round trip
  (records built in the test by a second implementation of the record and
  framing format), v2 leaves for the vendor keyset and v1 for ZeroKMS in one
  client, `ErrForeignKeyset` across backends, a wrong static key; AWS KMS in
  both modes through a fake `RoundTripper` that checks SigV4 with the host's
  credentials and binds the encryption context, with exact vendor call
  counts (derived: 1 `Decrypt`; wrapped: 1 `Decrypt` + 9
  `GenerateDataKey` for 3 rows of 3 sealed fields); an AWS refusal
  (`ErrForbidden`, code `stack_kms::backend`, vendor `aws-kms`); a failed
  credential source (`ErrTransport` plus the source's error, no request
  sent); and the option and record checks. `mise run go:test` passes;
  `golangci-lint` clean; `go generate ./...` changes nothing.
- **Not tested:** the Google Cloud, Azure and Vault clients through the Go
  host (their requests are covered in their own crates; the guest test
  checks their providers ask with the right vendor and scope). No live
  vendor test from Go.

### Deferred

- **Deferred (no ticket):** a vendor-only Go client, with no ZeroKMS
  credentials. Today the router's default keyset is ZeroKMS's, so NewClient
  still needs ZeroKMS. It needs a guest key source of `VendorKeySource`
  alone and a NewClient path with no `Credentials`.
- **Deferred (no ticket):** a root key TTL option in Go (the guest uses
  `DEFAULT_ROOT_KEY_TTL`, 5 minutes).
- **Deferred to CIP-5313:** the stack-kms side of the capability matrix.
  The Go package docs carry a short one.
