# Target-directed encryption derives for EQL Rust types

> **Status update, 2026-10-04.** Section 1's vertical slice (`TextEq` /
> `TextEqQuery`) is #971, ported to the `stack-encrypt` that now lives in this
> repository and depends on it by path and version. The broader draft this
> document describes below (every scalar domain, block-ORE/OPE/bloom terms,
> JSON/SteVec) was never committed. It needs `stack-encrypt` capabilities that
> have not landed (`EncryptFrom::KEYED`, `KeysetCipher::block_ore_term`); the
> `context_field` derive support it also needed has landed. References below to
> `cipherstash-suite` and publishing "the suite crates" are historical:
> stack-kms, stack-encrypt and stack-encrypt-derive now publish from this
> repository.

Status (2026-09-12): implemented locally in `stack` and the sibling `cipherstash-suite`
checkout; neither repository has been committed or published.

Validation completed:

- All scalar storage/query derives compile, with `Identifier` as their context.
- EQL's bindings suite passes with the feature enabled; canonical scalar round
  trips, context extensions, collection composition, and SteVec cases pass.
- Real ciphertexts and independent query terms pass PostgreSQL equality,
  OPE/block-ORE ordering, matching, containment, and extracted-entry checks.
- Suite tests and derive compile-pass/fail cases pass; lint passes on the suite's
  pinned Rust 1.90. The default EQL dependency tree contains no crypto runtime.
- The feature compiles for `wasm32-wasip1` with HTTP disabled.
- Generated Rust, TypeScript, and schemas were refreshed. Wire shapes are
  unchanged; ciphertext/header documentation now describes producer profiles.
- Root workflow wiring guards pass. Encryption integration dependencies live in
  the separate `eql-encryption-tests` crate, preserving lean default tests.

Release prerequisites remain: publish the suite crates, regenerate both EQL and
FFI lockfiles against registry dependencies, run the clean-package verification,
and perform live ZeroKMS authorization checks. Local tests use real cryptography
with the suite's test key source, which cannot establish authorization behavior.
No existing-column or mixed JS/Rust producer compatibility is claimed.

Local instructions and profile details are in
[`eql-bindings/README.md`](../../packages/eql/crates/eql-bindings/README.md).
The integration tests are in
[`tests/encryption`](../../packages/eql/tests/encryption/tests/stack_encrypt.rs).


Inspected on 2026-09-12: `stack` at `013e3ff3` and the local
`cipherstash-suite` branch `claude/cip-4037-keyset-cipher` at `ea2744b23`.
Suite implementation changes were applied against that commit.
Reconfirm the upstream API before implementation: this plan targets ongoing work,
not a released stack-encrypt contract.

Implement opt-in plaintext-to-EQL encryption and EQL-to-plaintext decryption on
the canonical `eql-bindings` types through the target-directed API.
Keep EQL encodings and domain policy here, reuse the generic derives and crypto
operations from `stack-encrypt`, and extend its macros only for missing generic
record behavior. Keep `eql-domains` dependency-free.

## Target-directed API scope

The scope is plaintext ↔ EQL conversion through these two traits:

| Trait | Implementation on an EQL type means |
| --- | --- |
| `EncryptFrom<P, C, Ctx>` | Construct this EQL payload from plaintext `P`, including its ciphertext, required terms and envelope metadata. |
| `DecryptInto<P, C, Ctx>` | Recover plaintext `P` from this stored EQL payload. |

`stack-encrypt-derive` already provides `EncryptFrom` and `DecryptInto`.
Reuse those derives. The blanket `EncryptInto` and `DecryptFrom` traits already
provide the reverse call-site spellings.

EQL types represent encrypted storage payloads or derived query terms. They are
the output of encryption and, when recoverable, the input to decryption.
Implementing the cipher-directed `Encrypt`/`Decrypt` traits on these types would
instead encrypt the already-encrypted representation and recover that
representation from an outer ciphertext. That is not a supported operation in
this design: do not implement or derive those traits on EQL payload or term
types. This is a semantic boundary, not deferred work. Those traits describe
the plaintext sources consumed by the target-directed adapters.

Storage payloads get the target-directed pair. Query operands get `EncryptFrom`
only: their terms cannot recover plaintext.
The dynamic `DomainPayload` and `QueryPayload` enums require an explicitly known
domain; neither existing derive supports enums. Do not infer a domain from
payload keys or promise an ambiguous `EncryptFrom<P>` on these enums.

## What the current code establishes

- [EQL's manifest](../../packages/eql/crates/eql-bindings/Cargo.toml) currently
  has no crypto runtime dependency. Its consumers include the native/WASM FFI
  and the bindings generator.
- [The bindings emitter](../../packages/eql/crates/eql-codegen/src/bindings.rs)
  owns scalar structs and query twins. Add attributes there and regenerate;
  hand-editing the generated domain files would fail the parity checks.
- [Shared wire fields](../../packages/eql/crates/eql-bindings/src/v3/terms.rs)
  are encoding wrappers: `Ciphertext(String)`, `Hmac256(String)`,
  `OreBlock256(Vec<String>)`, `OpeCllw(String)`, `BloomFilter(Vec<i16>)`.
  These need real leaf adapters before a record derive can work.
- [The envelope](../../packages/eql/crates/eql-bindings/src/lib.rs) fixes `v`
  to `SchemaVersion::CURRENT` and carries `Identifier { t, c }` in `i`.
  The version is an EQL schema version, not a crypto-format discriminator.
- [SteVec](../../packages/eql/crates/eql-bindings/src/v3/json.rs) uses a shared
  document key header and selector-dependent entry ciphertexts. It is not
  equivalent to independently encrypting a `Vec` of entries.
- In the suite, `stack-encrypt/src/target/mod.rs` encrypts through
  `KeysetCipher`, decrypts through `StackCipher`, and supplies constrained
  keyset decryption through blanket impls. `Pending` composes requests before
  dispatch. Some older examples in `docs/target-directed-encryption.md` still
  name `StackCipher` on the encrypt side; follow executable code.
- `stack-encrypt/src/cipher.rs` explicitly documents a new leaf framing/AAD;
  `sem/mod.rs` explicitly documents different term derivations from
  `cipherstash-client`. Neither old-row decryption nor mixed-producer search
  follows from a matching EQL JSON shape.
- EQL's existing `ob` producer uses `ore-rs::OreAes128ChaCha20`; the suite's
  `OreTerm` uses `cllw-ore`. An encoding adapter alone is not evidence that
  EQL's block comparator can consume that term.

## 1. Prove the contract with one vertical slice

Start with `TextEq` and `TextEqQuery`: a `String` round trip, a separately built
equality query, serialization into the actual PostgreSQL domain, and an equality
query against it. This exercises the identifier, ciphertext encoding, term
encoding and both conversion directions without the ordered-domain complications.

Record the result as an interoperability matrix covering:

- New Rust producer -> new Rust reader and query producer.
- Existing JS/FFI producer -> new Rust reader and query producer.
- New Rust producer -> existing JS/FFI reader and query producer.

Expected from today's sources: the first can be implemented; the other two need
explicit compatibility work. Prove the outcomes instead of treating all three
as the same promise.

Recommendation: target new stack-encrypt data first, with an explicitly selected
crypto profile for each column. New-profile query terms must never silently
probe a column indexed by the old producer. Define the supported reader/writer
pairing and migration/reindex requirement before exposing the feature. If mixed
JS/Rust access to existing columns is required at first release, make compatible
encryption, decryption and index derivation an upstream prerequisite.

Specify the `c` encoding independently of `v: 3`: EQL currently documents
MessagePack/base85 legacy records, whereas stack-encrypt freezes `SealedValue`
bytes. Select a distinguishable, versioned encoding and explicit decoder
behavior for unsupported profiles. Do not feed new bytes to the legacy decoder
or silently fall back after authentication failure. Verify whether that choice
can preserve the existing EQL schema; any required wire/API change must be
reviewed and versioned separately.

Exit condition: executable public-API example, actual SQL equality result, and
an agreed compatibility contract. Avoid rolling attributes across every domain
before this works.

## 2. Derive context from the identifier and implement the wire fields

The EQL payload's existing `i: Identifier` is the source of its base cryptographic
context. Encode its table and column components unambiguously through the
existing AAD/PRF context traits. Do not derive EQL context from Rust field names
or duplicate the identifier in context string literals. No new EQL context
wrapper is required merely to give `Identifier` these capabilities.

This needs a new generic derive capability. Source inspection confirms that
`stack-encrypt-derive/src/attrs.rs` accepts `context` only as `syn::LitStr`, and
`shape.rs::FieldContext` has only `Own(literal)` and `Caller` variants. There is
no field-based context selector today. The existing `from = field` selects
plaintext, not context. The existing struct mode uses an explicit context
prefix plus the plaintext field name; it does not infer a Rust struct name.

Proposed capability: mark a metadata field as carrying the record's base
context. `#[stash(context_field)] i: Identifier` expresses this in the implementation.
The macro remains generic over the field's type and knows nothing about EQL.

Define the two directions explicitly:

- Encryption receives the identifier alongside the plaintext, preferably through
  the existing `EncryptFrom` context argument. It validates/materializes that
  identifier first, uses it as context for every encrypted/term field, and stores
  the same value in `i`. It cannot read `self.i`: `Self` is the output being
  constructed. A scalar plaintext such as `String` cannot supply a table/column
  unless the API receives that information separately.
- Decryption reads `self.i` before moving out the ciphertext field, validates
  and encodes the identifier, and uses it to open the ciphertext. The context
  field contributes metadata, not a second recoverable plaintext field.

Use the phase-1 example to settle exact signatures and how optional caller
context extensions compose with this base. Extensions must agree on encrypt,
query and decrypt; they must never be silently discarded. Require a context
field to be available before cryptographic requests are built; do not introduce
a dependency cycle in which its value itself requires encryption.

Distinguish binding to the stored identifier from checking an expected storage
location. Altering `i` alone must invalidate decryption. Relocating the entire
payload, including unchanged `i`, is not detected by reading `i` alone. If the
caller needs destination validation, compare with an independently supplied
expected identifier. Keep that additional check explicit; do not claim that
field-based context proves where a payload was read from.

The missing implementations are on EQL's wire-field types, in an integration
module behind the optional `stack-encrypt` feature. The record derive delegates
to each field's `EncryptFrom`; it cannot infer an encryption algorithm or wire
encoding from a field wrapping `String` or `Vec`.

For example, `Hmac256::encrypt_from` derives a stack-encrypt `EqualityTerm` under
the context it receives, hex-encodes its bytes and wraps the result in
`Hmac256`. `Ciphertext::encrypt_from` similarly seals the source and encodes the
result; `Ciphertext::decrypt_into` decodes and opens it. These small trait
implementations are what this plan calls leaf adapters. They reuse crypto
operations rather than implementing new cryptography or context policy.

Implement `Decryptable` and `DecryptField` alongside these where the record
derive needs them: ciphertext is recoverable; one-way terms are skipped. Use
the existing keyset-decrypt blanket implementations.

The version field remains fixed metadata:
`#[stash(default = SchemaVersion::CURRENT)]`. The context-field capability
handles `i` explicitly; do not recover table/column names by splitting an
arbitrary context string or reference private expansion variables in a default
expression.

| Wire field | Adapter and proof required |
| --- | --- |
| `c` | Seal/open through stack-encrypt, encode/decode the agreed format, reject malformed or unsupported framing. Define one recoverable scalar representation; do not assume every `StackCipherText` is a single leaf. |
| `hm` | Encode `EqualityTerm` bytes in the exact hex representation EQL expects. |
| `op` | Encode `OpeTerm` and verify SQL byte-order comparisons for each supported plaintext family. |
| `ob` | Supply an EQL-compatible block-ORE producer. Reuse the existing primitive through a generic suite leaf adapter if possible; do not reinterpret CLLW bytes as block-ORE. |
| `bf` | Convert match positions to EQL's signed `i16` representation, including positions above 32767. Pin tokenizer, normalization and filter configuration identically for writes and probes. |

Keep crypto implementation and key handling in the suite. EQL adapters should
compose existing `Pending` operations with `map`/`zip`; they must not await each
field separately or acquire independent keys for ciphertext and its terms.

## 3. Generate the scalar derives and explicit plaintext mappings

Extend the bindings emitter to add feature-gated derives and attributes to
storage structs and their query twins. Derive the mapping from the existing
`ScalarKind`, using an exhaustive mapping in the generator rather than adding
runtime dependencies to `eql-domains`.

| EQL family | Initial canonical Rust plaintext |
| --- | --- |
| `smallint`, `integer`, `bigint` | `i16`, `i32`, `i64`, respectively |
| `real`, `double` | `f32`, `f64` |
| `text` | `String` |
| `boolean` | `bool`; storage only |
| `date`, `timestamp` | `chrono::NaiveDate`, `chrono::DateTime<Utc>` |
| `numeric` | `rust_decimal::Decimal` |
| `json` storage | `serde_json::Value` |

Start with one canonical source per domain; add additional source types only
with an explicit range/normalization contract. A generic wire wrapper must not
let a text value become an integer-domain payload. Use optional plaintext
dependencies/features where appropriate.

Audit upstream `Encrypt`/`Decrypt`, PRF and order-term support for each plaintext
source: these are prerequisites used by the target-directed leaf adapters,
not additional traits to derive on EQL records.
Date, timestamp, decimal and JSON support must be implemented in the trait-owning
crate or through EQL-owned plaintext adapters where missing; EQL cannot add a
foreign trait to a foreign plaintext type. This follows Rust's
[trait coherence rules](https://doc.rust-lang.org/reference/items/implementations.html#trait-implementation-coherence).
Pin temporal precision, decimal canonicalization, signed zero, infinities, NaN
policy and text ordering behavior against EQL's existing domain contract.

Cover storage-only, equality, OPE, block-ORE, match, and combined search shapes.
Text's ordered/search forms must preserve their separate HMAC equality term.
Query operands omit `c` and have no `DecryptInto` implementation. Test composition
inside caller-defined records and `Vec`/`Option` containers.

Preserve the fixed-value invariants of `SchemaVersion` and `SteVecForm` when
assembling payload metadata. Document the target-directed call sites for
encrypting values, creating query operands and recovering plaintext.

## 4. Complete the JSON/SteVec surface

Treat this as a separate implementation phase, required for a claim of complete
EQL-type coverage. The first scalar slice is useful but is not completion.

Implement the shared-header, selector, entry encryption and JSON reconstruction
operations in the suite as necessary, preserving EQL's one-key-per-document
contract, selector-dependent nonces/AAD and query semantics. Expose EQL leaf
adapters here and derive composite assembly only where the structure supports it.
Do not make a generic derive responsible for JSON traversal or nonce selection.

Cover `SteVecDocument`, a decryptable extracted `SteVecEntry` with its grafted
`h`/`i`/`v`, and encrypt-only `SteVecQuery`/`SteVecQueryEntry`. A bare entry missing
the necessary header/context must fail clearly. Include empty containers, arrays,
JSON null, path/value selectors and extracted-entry decryption.

Where aggregate domain enums need conversion helpers, dispatch using an explicit
domain and typed plaintext. Generic enum-derive support is unnecessary for the
concrete-domain API and should not become a prerequisite.

## 5. Validate behavior and wire it into CI

- Compile-pass/fail tests: canonical source types, rejected source/domain pairs,
  absent/invalid contexts, query-only decryption rejection, renamed dependencies,
  consumer crates and feature combinations. Run new generic macro cases in the
  suite's existing trybuild tests.
- Real crypto with the suite's test key source for deterministic, credential-free
  behavior checks: round trips, ciphertext/identifier tampering, caller context
  mismatches and explicit expected-identifier checks where provided,
  foreign keyset rejection and batched records/collections. Assert request counts
  and ensure failed preflight validation issues no key requests. Check that
  encryption stores exactly the identifier used for ciphertext and term context,
  that plaintext/Rust field renames do not change it, and that self-contained
  decryption is not mistaken for destination validation.
- PostgreSQL tests using genuinely encrypted payloads and separately generated
  query terms: insertion, equality, ordering, matching and SteVec operations.
  Use the existing credentialed SQLx fixture workflow for live coverage; do not
  replace it with synthetic or committed ciphertext blobs.
- Real ZeroKMS tests for descriptor/context enforcement and keyset behavior; the
  fake source cannot establish authorization semantics.
- Catalog-derived coverage assertions for every supported storage/query domain,
  including feature-gated families and explicit reasons for non-applicable traits.
- Regenerate Rust bindings through the emitter, then TS/JSON Schema artifacts.
  Run existing `test:crates`, `types:check`, `typescript:check` and relevant parity
  gates from `packages/eql`. Expect no TS/schema shape changes from derive-only
  integration; review any actual wire changes separately.
- Extend root `.github/workflows/test-eql.yml` to exercise the feature, default
  feature-free build, native and WASM/no-HTTP compilation. Keep Rust checks out
  of default JS test/build scripts. Update workflow wiring guards as required.

## 6. Make the result publishable

The dependency direction is `eql-bindings -> stack-encrypt -> stack-encrypt-derive`
and the suite's runtime dependencies. Keep the runtime dependency optional and
disable its default HTTP feature; expose HTTP initialization only through an
explicit feature choice. Verify the default EQL/FFI build does not acquire the
new runtime through feature unification.

For the spike use a pinned suite checkout and a local Cargo override. Do not
commit a developer-machine path. Before release, all transitive dependencies
must be publishable at registry versions and the packaged crate must verify in
a clean consumer outside both workspaces. Optional dependencies still need a
publishable resolution; they do not hide an unpublished crate from Cargo.
See Cargo's [dependency publication rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations).

Coordinate suite publication prerequisites first, then the EQL release using
this repository's existing lockstep process. The existing EQL CI job already
runs `cargo publish -p eql-bindings --dry-run --allow-dirty`; preserve that gate
and also verify the new feature from the packaged artifact. Do not alter release
arming/trusted-publishing configuration as part of adding derives.

Add rustdoc/examples, a compatibility/profile note, and a root
`.changeset/` entry for `@cipherstash/eql` (minor if additive; reassess if phase 1
requires a breaking wire contract). Check affected published skills. Actual
publication is a subsequent release operation.

## Suggested review sequence and completion criterion

1. Contract/spike: public call sites, profile/encoding decision and `TextEq` SQL proof.
2. Suite prerequisite PR: generic context-field derive support and missing
   leaf/input capabilities.
3. EQL PR: optional dependency, wire-field implementations, envelope metadata and
   generated scalar/query derives using the identifier as context.
4. JSON PR: storage JSON and SteVec support with shared-header tests.
5. Release-readiness PR: remaining CI/package checks, documentation and dependency pins.

Carry appropriate tests and changesets in each behavior-changing PR, rather than
deferring them all to the last one. Split block-ORE or scalar input prerequisites
further if they require substantial upstream changes.

Complete when every intended concrete EQL storage domain has `EncryptFrom` and
`DecryptInto`, query domains have `EncryptFrom`,
generated code stays authoritative, real ciphertexts insert/query/decrypt through
PostgreSQL, context and keyset failures are covered, and the packaged optional
feature builds from published dependencies. A derive expansion compiling by
itself is not sufficient evidence.
