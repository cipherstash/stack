# Key selection, lock context and provider capabilities

Date: 2026-10-25. Assessment accompanying the
[API implementation plan](2026-10-24-stack-encrypt-api-plan.md).

Status: recommendations for review, not accepted public signatures or an
implementation. The user requested plaintext-derived ZeroKMS keyset
selection, review of Vitamin C `AsyncCipher`, and optional lock-context
support without requiring future AWS KMS/Vault backends to emulate it.
The JSON operation contract remains under user review independently.

## Distinct roles

| Role | Selects/binds | Example |
| --- | --- | --- |
| Key selection | Provider key domain used to encrypt and derive index terms | ZeroKMS keyset ID or name selected from `tenant_id` |
| Ciphertext context | Application binding verified when opening ciphertext | Column + tenant scope + row ID |
| Search scope | Domain in which index/query terms compare | Column + tenant ID |
| Provider policy | Conditions the provider applies to key generation/retrieval | ZeroKMS lock context selecting authenticated JWT `sub` |

These are separate logical inputs, even where the protocol binds several
into its tag/AAD. A `ScopeKey<T>` does not select a ZeroKMS keyset by itself;
a keyset selector does not insert its source field into AAD; lock context
is not an alias for either ciphertext context or search scope. Sharing a
source value requires explicit declaration, not inference from a name.

## Current implementation evidence

- [StackCipher::keyset](../../packages/stack-encrypt/src/cipher.rs) accepts
  `IdentifiedBy` by UUID or name, resolves the keyset and its index key,
  and returns a bound `KeysetCipher`. The client has a bounded keyset cache
  and name-resolution freshness policy. `.default_keyset()` is already
  bound at initialization. Current initialization requires both
  `DataKeySource` and `IndexKeySource`.
- A sealed leaf carries the resolved keyset UUID. Client-scoped decrypt
  groups retrieval by the UUIDs in the leaves; a bound keyset can constrain
  which keyset is permitted. Names are lookup conveniences, not persistent
  key identities. See [ADR 0002](../../packages/stack-encrypt/docs/adr/0002-keyset-id-in-the-leaf-and-names-as-bounded-lookups.md).
- [Pending dispatch](../../packages/stack-encrypt/src/target/pending.rs)
  currently takes one selected keyset for generates and groups retrieves by
  their stored keyset IDs. It constructs generate/retrieve payloads without
  lock context and passes no unverified request context.
- [Key-source traits](../../packages/stack-kms/src/key_source.rs) and
  [payloads](../../packages/stack-kms/src/payload.rs) already model ZeroKMS
  lock-context lists, optional decryption policies and unverified context.
  They are ZeroKMS-specific abstractions used for provider injection/testing,
  not yet a neutral contract for arbitrary KMS backends. Returned key types
  also reflect the existing ZeroKMS/recipher integration.
- [TypeScript identity API](../../languages/typescript/packages/stack/src/identity/index.ts)
  accepts `.withLockContext({ identityClaim: ["sub"] })`. Its documented
  behavior is server resolution of claim values from the authenticating
  principal. Encrypt/decrypt operations pass that selector to protect-ffi;
  audit metadata travels separately as `unverifiedContext`.
- The pinned `zerokms-protocol` 0.12.31 `Context` enum includes `Tag`,
  `Value` and `IdentityClaim`. Its `RetrievedKey` currently exposes key
  material only; `stack-kms::DataKey` contains IV and key, not the original
  authentication tag returned by the proposed refinement flow. Supporting
  that flow remains a protocol/client response integration requirement,
  consistent with the user's earlier explanation of intended behavior.

## 1. Plaintext-derived keyset selection

Add a key-selection declaration to the existing target definition, parallel
to context/scope source selectors. A useful minimal portable form is an
explicit ID or name selector over a plaintext field:

```rust
// Proposed attribute fragment. tenant_id contains the actual keyset name.
#[stash(keyset(name(field = "tenant_id")))]
```

```rust
// Alternative: the selected field contains a keyset UUID, not an arbitrary
// application UUID assumed to be a keyset.
#[stash(keyset(id(field = "keyset_id")))]
```

Neither selector creates a keyset. Missing, unknown, unauthorized, disabled
or incorrectly typed keysets are errors; never fall back to the default.
A business tenant ID need not be a keyset name/UUID. Where they differ,
configure an explicit tenant-to-key mapping/resolver. Start with direct
selectors and a shared registered resolver contract; do not encode arbitrary
Rust callbacks in dynamic definitions. Pure mappings can return a selector;
network lookup belongs to the execution/provider layer, not the derive.

The existing manually selected form already fits the agreed API:

```rust
let tenant = cipher.keyset(IdentifiedBy::Name(user.tenant_id.clone().into())).await?;
let encrypted: EncryptedUser = user.encrypt_into(&tenant).await?;
```

The proposed derived route removes that repetition:

```rust
// EncryptedUser's definition declares how to select the keyset.
let encrypted: EncryptedUser = user.encrypt_into(&cipher).await?;
let encrypted: Vec<EncryptedUser> = users.encrypt_into(&cipher).await?;
```

`&cipher` is the client/provider executor which can resolve keysets; it is
not an unscoped request that silently encrypts under the default. Extend the
conversion executor capability to accept either a resolved keyset or a
client plus a declared selection recipe. The target's representation and
encryption operation description remain unchanged. Direct
`tenant_keyset.encrypt(value)` retains its accepted meaning.

Execution order:

1. Acquire guarded source ownership at request construction as already
   required. Validate target/options, input shape, selectors, role/capability
   requirements and every key-independent value check before provider I/O.
2. Evaluate the key-selection recipe from the guarded plaintext. Resolve
   selectors through the configured provider; pin each resolved identity
   for the duration of the request, including index derivation.
3. Partition a batch by resolved key identity, provider/authentication
   session and compatible request-level options. Preserve original result
   ordering; many tenants do not imply one remote call for the whole batch.
4. Use the selected keyset's index material for its searchable fields and
   mint data keys in the selected keyset. Persist the resolved identity,
   not a mutable name, in the ciphertext's provider metadata.

Define conflict behavior: a preselected keyset cannot silently be overridden
by a target's route. If both are provided, validate that the resolved route
matches the bound keyset, or reject the combination explicitly. No implicit
precedence or fallback. Errors requiring name resolution can only occur
after that resolution; the accepted preflight rule covers key-independent
checks, not provider facts unavailable locally.

For queries there is no plaintext user to inspect. The same target policy
must expose a caller-supplied tenant routing input or use an explicitly
selected keyset. A typed input may deliberately supply both key routing and
search scope; declaration determines both uses. Do not derive a keyset from
the email search value. Searching across multiple keysets is explicit
fan-out with a term per keyset, not one universally comparable query term.

Decrypt uses the stable key identity stored with the ciphertext, as today.
Do not re-resolve a historical keyset name and substitute its current target.
An expected tenant/keyset restriction can constrain retrieval, with any
historical key mapping supplied explicitly. Merely trusting a tenant field
returned alongside a ciphertext does not authenticate application tenancy;
row binding or trusted expected context supplies that separate check.
Likewise, choosing a keyset from caller-controlled plaintext is routing,
not permission to use every tenant keyset accessible to a service account.

## 2. Vitamin C AsyncCipher

**Packaging follow-up:** the user favors removal. The
[packaging recommendation](2026-10-25-stack-encrypt-packaging.md#retire-asynccipher)
now recommends retiring this trait and its application helpers as execution
moves into Stack, rather than adding the optional adapter considered below.
Vitamin C still has helper/test consumers to migrate; no removal has been
implemented.

The absence of `AsyncCipher` is intentional in the current design, not an
unexplained omission. [cipher.rs](../../packages/stack-encrypt/src/cipher.rs)
documents the reason, and implements the synchronous Vitamin C `Cipher`
through `MintedKeys` (seal) and `BoundKeys` (open).

Vitamin C 0.8.0 `AsyncCipher` takes leaf plaintext and derived AAD, with
`seal_many`/`open_many` operating on the leaves of one document. Stack's
executor retains the original provider descriptor and combines requests
across fields/documents/records before calling the leaf cipher. Leaf AAD
alone is not a reversible representation of those execution inputs.
Future routed keys and lock policies add more execution metadata rather
than removing the mismatch. The trait also requires `Sync` and `Send`
futures; Stack's provider traits use `MaybeSend` for native/WASM support.

Recommendation: retain Stack's batch/provider orchestration and Vitamin C's
leaf cryptography. Do not implement `AsyncCipher` on `StackCipher` merely to
claim trait symmetry, encode provider policy secretly into AAD, or lose
cross-record batching. An explicitly configured adapter could implement the
trait for a restricted use case with provider descriptor/key route/policy
already supplied, but it is not required for the public redesign and must
advertise its limitations. A general refactor would need a richer request
contract and evidence that batching/metadata/WASM behavior remain intact.

There is a smaller cleanup opportunity: each synchronous adapter currently
implements an unused half of `Cipher` by returning an error. Consider
separate seal/open capabilities or an internal adapter improvement during
the final dependency/packaging pass. Do not conflate that with requiring the
public Stack client to implement the async trait.

## 3. Lock context as an optional provider policy

Use a dedicated, typed ZeroKMS policy input, not the ordinary
`encrypt_with_context` argument and not a `SearchScope`. Proposed spelling:

```rust
use stack_encrypt::providers::zerokms::{LockContext, LockContextExt};

let lock = LockContext::identity_claim("sub");
let encrypted = user.encrypt_into(&tenant_keyset)
    .with_lock_context(&lock)
    .await?;
let user = User::decrypt_from(encrypted, &tenant_keyset)
    .with_lock_context(&lock)
    .await?;
```

This is illustrative module/method syntax pending the naming pass. The
operation builder retains owned plaintext guards while policy is attached.
The extension is present for a provider with the required capability; a
runtime-erased provider checks the equivalent capability before key I/O.
Ordinary encryption without this optional policy works on providers that
do not support it. A request/definition requiring it must fail on those
providers, never discard it or substitute literal AAD.

The input selects a claim **name**. ZeroKMS verifies the authenticating
principal and resolves its claim value; do not decode an unverified JWT in
the application and turn its `sub` into a caller assertion. Authentication
belongs to the configured provider/session. Use explicit, immutable
request/session binding when identities differ concurrently; avoid mutating
a global client's identity between operations.

Support explicit literal tag/value items through the same provider policy,
while distinguishing those caller assertions from principal-derived claims.
Missing claims or provider policy failures are errors with no retry without
the lock. Forward policy on generate and retrieve. A required policy can
live in the target definition so callers cannot accidentally omit it; an
operation may supply an undeclared optional policy, but cannot replace or
weaken a definition-required one. Define composition/conflict rules rather
than last-call-wins behavior. Policy selectors may need to be available on
reads; define their storage or required caller input without serializing
JWTs, credentials or claim values resolved by the provider.

Keep audit metadata (`UnverifiedContext`) separate: it is not trusted
identity, ciphertext context or a policy assertion. Preserve distinctions
between lock context and the protocol's separate decryption-policy feature;
do not silently reinterpret one as the other.

Index/query derivation may use an already-loaded deterministic index key
without generating/retrieving a data key. Therefore lock context on those
data-key endpoints does not by itself restrict who can derive search terms
or view query results. If search authorization is required, define that
capability separately; do not infer that the TypeScript query method's
acceptance of `withLockContext` proves the new index path is protected.
Do not implicitly make search scope principal-specific to emulate a lock.

Batching must preserve per-item lock inputs and separate incompatible
principal/provider sessions. If a provider supports per-payload policy,
retain it in each payload; if an option is request-wide, partition by it.
Any future data-key cache must respect policy/principal checking semantics;
a cache hit must not silently replace a required provider authorization or
audit event. This is a design requirement, not a claim of an existing cache
vulnerability. Do not broaden the current keyset/index-key cache into an
unqualified data-key authorization cache.

## Provider-neutral base and progressive capabilities

The public value/target model needs extensions, not replacement. The larger
refactor is the provider boundary, which currently imports ZeroKMS payloads,
UUID keyset IDs, policies, errors and returned key types directly.

Recommended capability split (working names):

| Capability | Required for |
| --- | --- |
| Data-key generation/recovery and protected key material | Ordinary opaque and structural encryption/decryption |
| Index-key support | Searchable targets and query derivation |
| Keyset resolution by ID/name | ZeroKMS-style keyset selectors; not every provider |
| Lock-context support, including claim selectors | ZeroKMS policy extension; not every provider |

Define a resolved provider key reference and versioned opaque recovery
metadata. Do not force every provider to supply a ZeroKMS UUID, IV/tag or
recipher response. A caller selects/configures a provider; ciphertext
metadata identifies a registered provider/key format, never arbitrary
network endpoints or credentials to execute. Keep ZeroKMS's key tag simple
to extract within its documented envelope profile for Rust/SQL consumers.
Other providers' metadata need not invent such a tag. Stable blob payload
encoding is independent of these provider-specific envelope profiles.

Future AWS KMS/Vault integrations implement the minimal capabilities they
offer. They need not implement lock context, named keysets or searchable
index-key management merely to encrypt an opaque value. The application
can configure its own tenant-to-provider-key mapping without representing
it as a native ZeroKMS keyset. A searchable target requires an explicitly
supported index-key strategy; the engine must not assume every data-key
backend supplies deterministic search keys automatically.

Refined-tag support also needs distinct stored/request tag and returned
original authentication-tag input. Preserve the user's intended ZeroKMS
flow when designing neutral responses; do not require that every provider
implements refinable tags or that a generic KMS returns that concept.

## Dynamic interoperability

Provider capabilities join target capabilities in discovery and definition
validation. Example provider-specific extension (proposed logical schema):

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

The field's declared type must admit the chosen selector; missing fields
are definition/input errors before provider resolution. Query routing
declares an equivalent caller input because it has no source record.
Providers and extensions are registered, versioned capabilities. Unsupported
required key selection/policy is an error during loading or binding to an
execution provider, before key I/O. Do not accept arbitrary extension maps
and ignore unfamiliar entries. Auth credentials stay in provider setup, not
in this declaration or persisted policy metadata.

Go generation uses named selectors/policies and the same validated dynamic
definition; provider-specific methods/capabilities are explicit. The
interoperability specification must include mixed-keyset batches, policy
inputs, capability refusals, key identity persistence and the distinctions
between authenticated claims and caller-supplied audit metadata.

## Implementation and acceptance work

1. Specify neutral key references/recovery metadata and optional capability
   traits without altering the accepted encrypt/decrypt conversion roles.
2. Add definition selectors and client-scoped routed execution. Cover ID
   versus name, explicit mappings, conflict errors and no default fallback.
3. Extend request planning/grouping to carry resolved route and provider
   policy. Preserve per-record ordering and guard lifetimes across async
   resolution/cancellation.
4. Wire ZeroKMS lock context through both generate/retrieve, including
   literal and principal-claim forms, and test required-policy enforcement.
5. Verify mixed-tenant batches, matching write/query keys, historical ID
   decrypt, wrong expected keysets, missing claims, unsupported-provider
   failures before I/O, and concurrent principal isolation. A minimal fake
   provider without keysets/locks/index keys must still encrypt opaque values.
6. Resolve refined-tag response support with the ZeroKMS client/protocol.
   Add integration fixtures without assuming the pinned API already returns
   the original tag.
7. Defer the `AsyncCipher` adapter/trait cleanup decision to the packaging
   pass; preserve the documented batching and WASM constraints meanwhile.

No implementation changes, protocol guarantees for future providers, or
completed security audit are claimed by this assessment.
