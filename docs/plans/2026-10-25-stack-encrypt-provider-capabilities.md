# Key selection, lock context, and provider capabilities

Dated 25 October 2026, with updates on 27 October 2026 and 7 November
2026. The last check was against `next` at commit `e4990e49b`. This assessment
accompanies the [API implementation plan](2026-10-24-stack-encrypt-api-plan.md).

## Status and requests

This document contains recommendations for review. The recommendations
are not accepted public signatures. Nothing in them is implemented. On 7
November 2026, no merged pull request implemented keyset routing from
plaintext, lock context, or the neutral provider split.

From 7 November 2026, the stored format of Go `v0.1.0-rc.3` must not
break. The stored format is what is written to the database, such as
ciphertext envelopes and search terms. [Tag refinement](2026-11-07-stack-encrypt-tag-refinement.md) replaces
the stored tag in place and adds a caveat list beside it. The list is
additive, so a payload without caveats is the rc.3 form. See the
[API
plan](2026-10-24-stack-encrypt-api-plan.md#the-stored-format-stays-compatible-with-go-rc3).

Dan asked for three things:

- ZeroKMS keyset selection derived from plaintext;
- a review of the Vitamin C `AsyncCipher` trait;
- optional lock context support, without requiring future backends, such
  as AWS Key Management Service (KMS) or Vault, to emulate it.

The JSON operation contract is live, in use as the release candidate Go
`v0.1.0-rc.3`.

## Summary of recommendations

1. Add a declaration that selects the keyset from a plaintext field. Never
   fall back to the default keyset.
2. Do not implement `AsyncCipher` on `StackCipher`. The packaging
   recommendation now proposes retiring the trait.
3. Add lock context as an optional, typed ZeroKMS policy input.
4. Split the provider boundary into a base capability for data keys and
   optional capabilities for everything else.

## Terms used in this document

| Term | Meaning |
| --- | --- |
| `DataKeySource` | The trait in `stack-kms` that generates fresh data keys and derives them again for stored ciphertexts |
| `IndexKeySource` | The trait in `stack-kms` that loads the deterministic index key of a keyset, used to derive search terms |
| `MaybeSend` | A bound that means `Send` on native targets and no bound on WebAssembly (WASM) |
| `Pending` | The request object that `StackCipher` returns. Settling it (awaiting it) sends the batched ZeroKMS calls |
| AAD | Additional authenticated data: data that encryption checks for one ciphertext, but does not encrypt. Stack Encrypt builds it from the context. See [Context and AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad) |
| Context | Data that a ciphertext is tied to, such as a column name or a row ID. Decryption needs the same context. See [Context and AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad) |
| Key I/O | Any request to the key provider to generate or retrieve a key |
| Keyset | A ZeroKMS key domain. Data keys are generated in a keyset, and each keyset has a deterministic index key |
| Lock context | A ZeroKMS policy that ZeroKMS applies when it generates or retrieves a data key, such as a claim of the authenticated JSON Web Token (JWT) |
| Provider | A key provider: the KMS backend that generates and retrieves data keys, such as ZeroKMS. Not `stack_kms::KeyProvider`, which is a source of client keys |
| Vitamin C | CipherStash's library of cryptographic primitives |

## Four separate roles

| Role | What it selects or binds | Example |
| --- | --- | --- |
| Key selection | The provider key domain used to encrypt and to derive index terms | A ZeroKMS keyset ID or name selected from `tenant_id` |
| Stored context | Every part of a value's context, under which the key and the AAD derive. Verified when a ciphertext is opened | The column, a tenant scope, and a row binding |
| Query context | The scopes of a context, under which search terms derive and compare | The column and a tenant scope |
| Provider policy | Conditions the provider applies when it generates or retrieves a key | ZeroKMS lock context that selects the `sub` claim of the authenticated JWT |

These four roles are separate logical inputs, even where the protocol binds
several of them into its tag or AAD:

- A scope does not select a ZeroKMS keyset by itself.
- A keyset selector does not add its source field to the AAD.
- Lock context is not another name for the stored context or the query
  context.

For two roles to share a source value, the definition must declare it
explicitly. The engine must not infer it from a name.

## 1. Keyset selection derived from plaintext

Recommendation: add a key selection declaration to the existing target
definition, beside the declaration's scopes and bindings. A useful
minimal portable form is an explicit selector, by ID or by name, over a
plaintext field:

```rust
// Proposed attribute fragment. tenant_id contains the actual keyset name.
#[stash(keyset(name(field = "tenant_id")))]
```

```rust
// Alternative: the selected field contains a keyset UUID, not an arbitrary
// application UUID assumed to be a keyset.
#[stash(keyset(id(field = "keyset_id")))]
```

Neither selector creates a keyset. A missing, unknown, unauthorised,
disabled, or incorrectly typed keyset is an error. Never fall back to the
default keyset.

A business tenant ID does not have to be a keyset name or UUID. Where the
two differ, configure an explicit mapping or resolver from tenant to key.

Start with direct selectors and one shared contract for registered
resolvers. Do not encode arbitrary Rust callbacks in dynamic definitions.
A pure mapping can return a selector. A network lookup belongs in the
execution or provider layer, not in the derive.

### Selecting the keyset by hand and by declaration

The existing form, where the caller selects the keyset by hand, already
fits the agreed API. This example uses the `IdentifiedBy::name`
constructor that the [API
plan](2026-10-24-stack-encrypt-api-plan.md#constructors-for-identifiedby)
proposes:

```rust
let tenant = cipher.keyset(IdentifiedBy::name(&user.tenant_id)?).await?;
let encrypted: EncryptedUser = user.encrypt_into(&tenant).await?;
```

The proposed route, derived from the declaration, removes that
repetition:

```rust
// EncryptedUser's definition declares how to select the keyset.
let encrypted: EncryptedUser = user.encrypt_into(&cipher).await?;
let encrypted: Vec<EncryptedUser> = users.encrypt_into(&cipher).await?;
```

`&cipher` is the executor for the client and provider. That executor can
resolve keysets. `&cipher` is not a request without a scope that silently
encrypts under the default keyset.

Extend the capability of the conversion executor so that it accepts
either a resolved keyset, or a client with a declared selection recipe.
The target's representation, and the description of its encryption
operation, do not change. A direct `tenant_keyset.encrypt(value)` keeps
its accepted meaning.

### Execution order

1. When the request is built, take guarded ownership of the source, as
   already required. Before any provider I/O, validate:
   - the target and its options;
   - the input shape;
   - the selectors;
   - the role and capability requirements;
   - every check on values that does not need a key.
2. Evaluate the key selection recipe on the guarded plaintext. Resolve the
   selectors through the configured provider. Keep each resolved identity
   fixed for the whole request, including index derivation.
3. Split a batch into groups by resolved key identity, by provider and
   authentication session, and by compatible options at the request level.
   Return results in the original order. A batch with many tenants does
   not mean one remote call for the whole batch.
4. Use the index material of the selected keyset for its searchable
   fields, and generate data keys in the selected keyset. Store the
   resolved identity in the ciphertext's provider metadata, not a name
   that can change.

### A keyset selected both beforehand and by the target

Define the behaviour for this conflict. A target's route must not silently
override a keyset selected beforehand. If both are given, either check
that the resolved route matches the bound keyset, or reject the
combination explicitly. Neither takes precedence implicitly, and there is
no fallback.

Errors that need name resolution can only happen after that resolution.
The accepted preflight rule covers checks that need no key. The rule does
not cover facts about the provider that are not available locally.

### Queries

A query has no plaintext user record to inspect. So the same target
policy must either expose a tenant routing input that the caller supplies,
or use a keyset selected explicitly. One typed input can deliberately
supply both the key route and the query context. The declaration decides
both uses.

Do not derive a keyset from the email address being searched for. To
search across several keysets, fan out explicitly, with one query term for
each keyset. No single query term compares across all keysets.

### Decryption

Decryption uses the stable key identity stored with the ciphertext, as it
does today. Do not resolve a historical keyset name again and use what it
points to now. An expected tenant or keyset can restrict key retrieval,
with any historical key mapping supplied explicitly.

Trusting a tenant field returned beside a ciphertext does not authenticate
the application's tenancy. Row binding, or a trusted expected context,
makes that separate check. In the same way, choosing a keyset from
plaintext that the caller controls is routing. That choice does not give
permission to use every tenant keyset a service account can access.

## 2. Vitamin C AsyncCipher

Recommendation: do not implement `AsyncCipher` on `StackCipher`.
`AsyncCipher` is the Vitamin C trait that seals and opens the leaves of
one document asynchronously.

### Follow-up from packaging

Dan favours removing the trait.

The
[packaging recommendation](2026-10-25-stack-encrypt-packaging.md#retire-asynccipher)
now recommends retiring this trait and its application helpers as
execution moves into Stack. That replaces the optional adapter considered
below. Vitamin C still has helpers and tests that use the trait. Those
helpers and tests need to be migrated. Nothing has been removed yet.

### Why Stack leaves out AsyncCipher

Stack leaves out `AsyncCipher` on purpose. The current design does not
omit it by accident.
[cipher.rs](../../packages/stack-encrypt/src/cipher.rs) documents the
reason. That file implements the synchronous Vitamin C `Cipher` trait
through two types: `MintedKeys` seals, and `BoundKeys` opens.

In Vitamin C 0.8.0, `AsyncCipher` takes the plaintext of a leaf and its
derived AAD. Its `seal_many` and `open_many` work on the leaves of one
document. The trait does not match Stack in three ways:

- Stack's executor keeps the original provider descriptor. The executor
  combines requests across fields, documents, and records before it calls
  the leaf cipher. The AAD of a leaf alone cannot be turned back into
  those execution inputs.
- Future routed keys and lock policies add more execution metadata. They
  do not remove the mismatch.
- The trait requires `Sync` and `Send` futures. To support both native
  and WASM builds, Stack's provider traits use `MaybeSend`.

### A smaller clean-up

Each synchronous adapter now implements the half of `Cipher` that it does
not use, by returning an error. During the final pass on dependencies and
packaging, consider separate capabilities for sealing and opening, or an
improvement to the internal adapter. Keep this clean-up separate from the
question of whether the public Stack client implements the async trait.

## 3. Lock context as an optional provider policy

Recommendation: pass lock context as its own typed ZeroKMS policy input.
It is provider policy, not context, so it is not a `Scope` or a `Bind`.
It is not a step after an entry point either. The plan's entry points
come in pairs, `x` with `x_with_context`, and nothing is chained after
them.

So the lock context is set on the keyset before the call, and every call
through that keyset carries it. Proposed spelling:

```rust
use stack_encrypt::providers::zerokms::LockContext;

let lock = LockContext::identity_claim("sub");
let locked = tenant_keyset.with_lock_context(&lock);

let encrypted: EncryptedUser = user.encrypt_into(&locked).await?;
let user = User::decrypt_from(encrypted, &locked).await?;
```

The module and method names illustrate the idea until the naming review.
A keyset with a lock context is a keyset, so `Planned` and the marker
queries take it without change. The extension is present for a provider with the required
capability. A provider whose type is erased at runtime checks the same
capability before key I/O.

Ordinary encryption without this optional policy works on providers that
do not support it. On those providers, a request or definition that
requires lock context must fail. The request must never discard the
policy, or substitute literal AAD.

### Claims come from the provider

The input selects the **name** of a claim. ZeroKMS verifies the principal
that authenticated, and resolves the value of its claim. Do not decode an
unverified JWT in the application and turn its `sub` into an assertion by
the caller. Authentication belongs to the configured provider or session.

When different identities are active at the same time, bind each request
or session to its identity explicitly and immutably. Do not change the
identity of a global client between operations.

### Rules for lock context

- Support explicit literal tag and value items through the same provider
  policy. Keep these assertions by the caller distinct from claims derived
  from the principal.
- A missing claim, or a failure of the provider policy, is an error. Do
  not retry without the lock.
- Send the policy on both key generation and key retrieval.
- A required policy can be part of the target definition, so callers
  cannot leave it out by mistake. An operation can supply an optional
  policy that the definition does not declare. An operation cannot replace
  or weaken a policy that the definition requires.
- Define rules for combining policies and for conflicts between them. Do
  not let the last call win.
- Reads may need the policy selectors. Define how the selectors are
  stored, or which input the caller must supply. Do not serialise JWTs,
  credentials, or claim values that the provider resolved.
- Keep audit metadata (`UnverifiedContext`) separate. Audit metadata is
  not a trusted identity, ciphertext context, or a policy assertion.
- Keep lock context distinct from the protocol's separate decryption
  policy feature. Do not silently treat one as the other.

### Lock context does not protect search

Deriving index and query terms can use a deterministic index key that is
already loaded, without generating or retrieving a data key. So lock
context on the data key endpoints does not by itself restrict who can
derive search terms or see query results.

If search needs authorisation, define that capability separately. The
TypeScript query method accepts `withLockContext`. That does not prove
that the new index path is protected. Do not imitate a lock by making the query context specific to a
principal implicitly.

### Batching and caching with lock context

Batching must keep the lock inputs of each item. Batching must also keep
incompatible principal sessions and provider sessions apart. If a provider
supports a policy on each payload, keep the policy in each payload. If an
option applies to the whole request, split the batch by that option.

Any future cache of data keys must respect the semantics of checking
policy and principal. A cache hit must not silently replace a provider
authorisation or audit event that is required. This is a design
requirement. It does not claim that an existing cache has a
vulnerability. Do not widen the current cache of keysets and index keys
into a data key cache that authorises without those checks.

## A neutral provider base with optional capabilities

The public model of values and targets needs extending, not replacing. The
larger refactor is at the provider boundary. That boundary now imports
ZeroKMS payloads, UUID keyset IDs, policies, errors, and returned key
types directly.

The recommended split of capabilities, with working names:

| Capability | Required for |
| --- | --- |
| Data key generation and recovery, and protected key material | Ordinary opaque and structural encryption and decryption |
| Index key support | Searchable targets and query derivation |
| Keyset resolution by ID or name | ZeroKMS-style keyset selectors. Not every provider offers it |
| Lock context support, including claim selectors | The ZeroKMS policy extension. Not every provider offers it |

### Key references and metadata

Define a reference to a resolved provider key, and versioned opaque
metadata for recovering the key. Do not force every provider to supply a
ZeroKMS UUID, an IV with its tag, or a recipher response.

A caller selects and configures a provider. Ciphertext metadata identifies
a registered provider and key format. The metadata never names arbitrary
network endpoints or credentials to execute.

Keep ZeroKMS's key tag simple for Rust and SQL consumers to extract,
within its documented envelope format. Other providers' metadata does not
need to invent such a tag. The stable encoding of blob payloads does not
depend on the envelope format of each provider.

### Future providers

Future integrations with AWS KMS or Vault implement the minimal
capabilities they offer. To encrypt an opaque value, they do not need lock
context, named keysets, or management of index keys for search. The
application can configure its own mapping from tenant to provider key,
without representing it as a native ZeroKMS keyset.

A searchable target requires an index key strategy that is explicitly
supported. The engine must not assume that every data key backend supplies
deterministic search keys automatically.

### Tag refinement

[Tag refinement](2026-11-07-stack-encrypt-tag-refinement.md) needs two
distinct inputs: the refined tag and its caveats, stored and sent in the
request, and the original authentication tag returned.
When designing neutral responses, keep the ZeroKMS flow that Dan
intended. Do not require every provider to implement refinable tags, or a
generic KMS to return that concept.

## Dynamic interoperability

Discovery and definition validation cover provider capabilities as well as
target capabilities. This example shows a proposed logical schema for an
extension specific to one provider:

```json
{
  "provider": "zerokms",
  "key_selection": {
    "keyset": { "by": "name", "encrypt": { "field": "tenant_id" } }
  },
  "provider_policy": {
    "zerokms": {
      "lock_context": [{ "identity_claim": "sub" }]
    }
  }
}
```

Rules for the dynamic definition:

- The field's declared type must allow the chosen selector. A missing field
  is a definition or input error, before the provider resolves anything.
- Query routing has no source record, so it declares an equivalent input
  that the caller supplies.
- Providers and extensions are registered, versioned capabilities.
- Unsupported required key selection or policy is an error when the
  definition is loaded or bound to an execution provider, before key I/O.
- Do not accept arbitrary extension maps, and do not ignore unfamiliar
  entries.
- Authentication credentials stay in the provider setup. They are not in
  this declaration or in stored policy metadata.

Go code generation uses named selectors and policies, and the same
validated dynamic definition. Methods and capabilities specific to a
provider are explicit. The interoperability specification must cover:

- batches with several keysets;
- policy inputs;
- refusals because a capability is missing;
- how key identities are stored;
- the difference between authenticated claims and audit metadata that the
  caller supplies.

## Implementation and acceptance work

1. Specify neutral key references, recovery metadata, and optional
   capability traits. Do not change the accepted conversion roles for
   encryption and decryption.
2. Add selectors to definitions, and routed execution through the client.
   Cover selection by ID compared with by name, explicit mappings,
   conflict errors, and no fallback to the default.
3. Extend request planning and grouping to include the resolved route and
   the provider policy. Across asynchronous resolution and cancellation,
   keep the order of records. Keep the lifetimes of guards too.
4. Pass ZeroKMS lock context through both key generation and key
   retrieval, in both the literal form and the principal claim form. Test
   that a required policy is enforced.
5. Test these cases:
   - batches with several tenants;
   - matching keys for writes and queries;
   - decryption by historical ID;
   - wrong expected keysets;
   - missing claims;
   - failures for unsupported providers, before I/O;
   - isolation between principals active at the same time.

   A minimal fake provider without keysets, locks, or index keys must
   still encrypt opaque values.
6. Settle support for tag refinement in responses with the ZeroKMS
   client and protocol. Add integration fixtures without assuming the pinned API
   already returns the original tag.
7. Leave the decision on the `AsyncCipher` adapter and the trait clean-up
   to the packaging pass. Until then, keep the documented constraints on
   batching and WASM.

This assessment does not claim any implementation changes, any protocol
guarantees for future providers, or a completed security audit.
