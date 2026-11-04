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
