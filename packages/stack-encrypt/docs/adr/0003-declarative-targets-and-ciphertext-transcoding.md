---
status: accepted
date: 2026-09-12
supersedes: ADR-0001
---

# Declare target operations and transcode native encryption output into records

The current target-directed extension gives each output implementation the
plaintext and cipher, allowing it to replace the plaintext's Vitamin C encoding;
the initial EQL integration demonstrated this by serializing plaintext with
MessagePack and encrypting the resulting bytes. Targets will instead declare
their operations and context requirements, with Stack Encrypt executing the
operations and constructing the target through a visitor over native encryption
output. This preserves Vitamin C's plaintext contract while supporting derived
records without an additional serialized buffer or generic intermediate tree.

This records the accepted architecture, implemented by the core operation
descriptions, native readers, and derives in this crate. It supersedes
[ADR-0001](0001-context-optional-cipher-directed-path.md) as the current context
and target-extension contract, carrying forward the context policies stated
below. EQL-shaped integration tests exercise the consumer contract; wiring the
actual EQL crate and extending Vitamin C plaintext coverage remain separate work.

## Decision

`EncryptFrom<P>` remains the declaration that an encrypted target can be produced
from plaintext `P`. Its derive supplies an associated `Context` type, an operation
description assembled from core-supported operations, and a visitor that builds
the target from their results. It has no overridable method receiving both the
plaintext and cipher. The cipher executes the declaration: its ciphertext
operation calls Vitamin C's `Encrypt`, and its term operations use the respective
PRF or ordering capabilities. A target that only produces terms requires those
capabilities without unnecessarily requiring recoverable encryption.

The output type determines the operations. Semantic field types and explicit
derive configuration identify ciphertext, terms, defaults, and context metadata;
untyped bytes or field names alone cannot identify an operation. Settings such as
normalization and tokenization must be declared where the types do not determine
them. Callers provide plaintext and the target's context, not a separate plan:

```rust
// Consumer call-site shape; Identifier and TextEq belong to EQL.
let identifier = Identifier::for_column("users", "email")?;
let encrypted: TextEq = keyset.encrypt_as(&email, identifier).await?;
```

For EQL, the encryption context is `NonEmpty<Identifier>`, with the underlying
identifier stored in `i`. Its table and column components supply the context for
the ciphertext, terms, and ZeroKMS descriptor. EQL does not infer context from
Rust struct/field names or duplicate the identifier in literal attributes. The
storage envelope's `c`, `hm`, and other field names do not add plaintext map-entry
context derivations. Plaintext maps continue to use Vitamin C's own derivations.

A target can require no caller context (`Context = ()`) when its declaration
already supplies the contexts its operations require. EQL ciphertext and term
operations still require nonempty context. Context encoding and emptiness proofs
remain Vitamin C's responsibility. The cipher-directed API continues to accept
any supported context, including `()`, and remains available; this decision does
not close it. A concrete associated context type does not implicitly accept
arbitrary context extensions; any extension facility must preserve the declared
base context and be specified explicitly.

Transcoding consumes native encryption output through a custom encrypted-data
protocol. It distinguishes sealed leaves, sequences, maps, authenticated absence
and empty-container markers, passthrough metadata, and typed terms. Readers expose
existing outputs directly to target visitors; they do not first construct another
universal value tree. The existing pending cipher structure, batching state, native
ciphertext output, and final target allocations remain legitimate. This is not a
promise of zero allocation or of eliminating the cipher's own structures.

`DecryptInto<P>` declares how to inspect the encrypted target, select recoverable
ciphertext, and obtain its context so core code can invoke Vitamin C's `Decrypt`.
For EQL, stored `i` is validated before key retrieval; an externally supplied
expected identifier is checked against it when destination validation is wanted.
Terms do not recover plaintext, and query-only targets have no `DecryptInto`.
Construction and inspection readers are supporting protocols, not additional
public `FromEncrypted` / `IntoEncrypted` derives. EQL encrypted payloads do not
implement the plaintext-side `Encrypt` / `Decrypt` traits.

## Considered options

- **Keep arbitrary target encryption methods, with documentation or an added
  `P: Encrypt` bound.** A bound cannot require a method body to call that
  implementation. A default method remains overridable. Neither prevents the
  EQL plaintext-serialization bypass.
- **Use a core-owned encoded-ciphertext wrapper with a format adapter.** This
  protects the covered leaf conversion and can also avoid intermediate formats,
  but does not supply a shared structural protocol for records, collections,
  metadata, and terms. Its responsibility separation informs the chosen design.
- **Use Serde as the transcoding protocol.** The `async-sync` spike demonstrates
  direct visitor-driven construction from a cipher's normal output without a
  serialization round trip. We adopt that pattern with an encrypted-data model:
  byte strings and ordinary null/empty values do not express the distinctions
  needed to preserve sealed leaves and authenticated structural markers.

## Consequences

- The target traits, derives, container composition, and affected bindings need
  coordinated changes. The existing API is unpublished, but local call sites
  still need migration. Supported operation descriptions must not admit arbitrary
  plaintext-and-cipher callbacks that recreate the bypass. The guarantee concerns
  target-directed execution, not all code a caller could write with a cipher.
- The implementation must preserve batching and keyset scope, move outputs through
  consuming readers, and retain authenticated markers and cryptographic map keys.
  Unsupported shapes must fail explicitly. Stored context is not inherently
  trusted merely because it was parsed, and metadata/terms must not be presented
  as AEAD-authenticated values by the transcoder.
- Missing plaintext `Encrypt` / `Decrypt` capabilities belong in Vitamin C, with
  encoding, precision, and domain behavior specified there. EQL must not restore
  a Serde fallback or substitute tagged FFI wrappers for direct Rust plaintext
  implementations without an explicit representation decision.
- Verification must include cross-opening ciphertext between the canonical and
  target-directed paths, plaintext types without Serde implementations, required
  context checks, marker and shape handling, query-only behavior, and batching.
  A round trip confined to one adapter is insufficient evidence of compatibility.
- This decision does not establish interoperability with existing
  `cipherstash-client` EQL producers or change persisted formats. JSON/SteVec's
  shared document key and selector semantics need their own supported operations;
  a scalar transcoder does not settle that design. Operation-description and
  reader signatures, generic-target context ergonomics, and those document
  operations must be validated before claiming complete EQL coverage.
