# Context sources and storage: directional API examples

Date: 2026-10-24. Design exploration accompanying the
[API review log](2026-10-24-stack-encrypt-api-review.md) and
[complete public workflow examples](2026-10-24-stack-encrypt-public-examples.md).

**Everything introduced here is proposed syntax, not an implemented API.**
The purpose is to compare context behavior across the meaningful source and
storage combinations before selecting attributes or changing traits. The
`Ciphertext` and `passthrough` proposals are inherited from the workflow draft.

## Recommendation: directional sources, separate storage

Borrow Serde's nested directional attribute style: it supports separate
serialization and deserialization names within one `rename` attribute.
See [Serde's field attributes](https://serde.rs/field-attrs.html).

For encryption, use direction names to say **where to obtain context**:

```rust
#[stash(context(
    prefix = "users",
    encrypt(field = "id"),
    decrypt(field = "id")
))]
```

The two `field` selectors refer to different objects: the plaintext input
when encrypting, and the encrypted input when decrypting. They must yield the
same typed context value. Unlike a Serde rename, these are not independent
cryptographic names: changing the context value or its shape between the two
directions prevents decryption.

For the common case where both directions use the same Rust field name,
the recommended shorthand is:

```rust
#[stash(context(prefix = "users", field = "id"))]
```

This expands exactly to `encrypt(field = "id"), decrypt(field = "id")`.
It still reads two different objects: the plaintext input on encrypt and the
encrypted input on decrypt. It does not copy or store the field implicitly;
the output layout must make that value available, normally with passthrough.
Use the explicit directional form when the names or sources differ.

Use a separate field annotation to **store the computed context** when it is
not already carried by ordinary passthrough fields:

```rust
#[stash(from_context)]
scope: u64,
```

`from_context` fills an output metadata field from the computed logical
context. It does not choose the context source. A passthrough source field
can already carry the context value, in which case no `from_context` field
is needed. No new source-side encryption methods or public `encrypt_as`
entry point are introduced.

This is preferable to bare `context(in)` / `context(out)`: either term could
mean an operation direction, an input/output object, or storing a value.
`encrypt`, `decrypt`, and `from_context` give those roles distinct names.

## Proposed vocabulary and semantics

| Syntax inside `context(...)` | Meaning |
| --- | --- |
| `prefix = "users"` | Static base for this layout's field contexts |
| `field = "id"` | Shorthand for both `encrypt(field = "id")` and `decrypt(field = "id")` |
| `encrypt(caller = u64)` | Obtain the logical context from a required `u64` argument |
| `encrypt(field = "id")` | Obtain it from the plaintext input's `id` |
| `decrypt(caller = u64)` | Obtain it from a required `u64` argument on decrypt |
| `decrypt(field = "scope")` | Obtain it from the encrypted input's cleartext `scope` |
| `encrypt(tuple(field = "tenant_id", field = "id"))` | Build one ordered, typed pair from plaintext fields |
| `decrypt(tuple(field = "id", caller = u64))` | Build one pair from a stored field and the decrypt argument |

`tuple(...)` is a declarative selector, not a Rust expression or a function
that gets access to keys. It can nest. `field` names resolve at compile time;
the first design supports direct fields, not arbitrary paths or callbacks.
There is at most one caller argument selector per direction; use a tuple or
typed context object as that argument when it carries several values.

Use either the shared `field` shorthand or both explicit directional
selectors. For the initial API, reject mixing the shorthand with directional
selectors instead of inventing precedence rules. That keeps the expansion
predictable; a record with asymmetric names uses the explicit form.
`context = "users"`
remains the existing simple spelling for a static prefix with optional caller
extensions; it is used in scenario 0.

### Composition rule

Call the logical row context `R`. For a field named `name`, its static base is
`B = ("users", "name")` and its effective context is `(B, R)`. With only a
static prefix and no extension it is just `B`, not `(B, ())`.

The selector's result is **one structured value**. A pair `(tenant_id, id)`
produces `(("users", "name"), (tenant_id, id))`, not
`((("users", "name"), tenant_id), id)`. `from_context` stores `R`, not the
field-dependent effective context. Static prefixes and field identities are
reconstructed from the declaration.

Names in this proposal do not change existing byte encodings. Mapping new
selectors onto the existing context machinery must preserve types, order,
grouping, and descriptor rendering. A new explicit selector is a new
declaration; it must not silently reinterpret existing stored data.

### Storage and expected context

When all of `R` can be reconstructed from stored fields, the default decrypt
call uses those fields. The caller may additionally supply an expected `R`
through the existing `ExpectedContext<R>` pattern: check equality first, then
use the stored value. That expected value is **not another extension**.

When a decrypt selector needs a caller argument, that argument is required
to construct `R`; no no-context convenience is available. It is not an
expected-value check on context already fully available from the record.

If a future caller needs both a required input and a separate expectation
on the assembled `R`, use a distinct checked-context input or a named API.
Do not overload one unlabelled argument to mean both. That combined check
API remains outside this proposal; scenario 7 makes the need visible.

## Scenario matrix

| Scenario | Encrypt obtains context from | Context available in stored output | Decrypt obtains context from |
| --- | --- | --- | --- |
| 0 | Static prefix; no row context | Declaration | Declaration |
| 1 | Caller argument | Not stored | Caller argument |
| 2 | Caller argument | Dedicated metadata field | Metadata field |
| 3 | Plaintext `id` | No cleartext copy; `id` itself is encrypted | Caller argument |
| 4 | Plaintext `id` | Passthrough `id` | Stored `id` |
| 5 | Plaintext `(tenant_id, id)` | Two passthrough fields | Same pair of stored fields |
| 6 | Plaintext `id` plus caller scope | Dedicated pair-valued metadata field | Stored pair |
| 7 | Plaintext `id` plus caller scope | Only `id` is stored in cleartext | Stored `id` plus caller scope |
| 8 | Plaintext `(tenant_id, id)` | Neither component is stored in cleartext | Caller supplies the pair |

An encrypted copy of a context field does not make that context available
before decrypt. Scenarios 3 and 8 retain encrypted copies to recover the
complete plaintext object; callers still need the context independently.

## Shared code for the examples

Each scenario defines an output type and an async function. Combine this
prelude, the scenario blocks, and the final `main` into one candidate program.
They use real file serialization through the same helper, so no example
relies on a context value being secretly carried inside an in-memory handle.
All use proposed APIs and therefore cannot yet be typechecked against Stack.

Dependencies match the workflow draft: Stack Encrypt, Serde with derives,
serde_json, tempfile, and Tokio. ZeroKMS credentials are required once these
APIs exist. `scope = 7` in caller examples is external application context,
not a keyset selector or an authorization credential.

```rust
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use stack_encrypt::{
    Ciphertext, DecryptFrom, DecryptInto, EncryptFrom, EncryptInto, NonEmpty,
    StackCipher,
};
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, PartialEq)]
struct User {
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

fn sample_user() -> User {
    User {
        id: 42,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
        created_at: 1_700_000_000,
    }
}

// The candidate Ciphertext Serde contract encodes its canonical envelope.
fn store_and_reload<T: Serialize + DeserializeOwned>(value: &T) -> Result<T> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("record.json");
    std::fs::write(&path, serde_json::to_vec(value)?)?;
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
```

## 0. Static prefix only

This is the baseline. There is no dynamic row context to store or supply.
It retains the existing static-context form and proposed passthrough support.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User, context = "users")]
struct StaticUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_0() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_user();

    let stored: StaticUser = user.encrypt_into(&keyset).await?;
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from(loaded, &cipher).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

For this shorthand, caller extensions remain available as previously agreed:
encrypt and decrypt must receive the same extension. The remaining examples
use explicit directional selectors, so their argument requirements follow
those selectors; there is no additional implicit extension layered on top.

## 1. Caller context, not stored

`scope` is absent from the output. The caller must provide it again. A
plaintext `id` in this layout is unrelated to the chosen context source.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User)]
#[stash(context(
    prefix = "users",
    encrypt(caller = u64),
    decrypt(caller = u64)
))]
struct ExternalScopeUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_1() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_user();
    let scope = 7_u64;

    let stored: ExternalScopeUser = user
        .encrypt_into_with_context(&keyset, scope)
        .await?;
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from_with_context(loaded, &cipher, scope).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

Logical context: `7_u64`. Effective name context: `(("users", "name"), 7_u64)`.

## 2. Caller context, stored in an output metadata field

The source is still the function argument. `from_context` stores its value;
the decrypt selector explicitly chooses that stored field. `scope` is output
metadata, not a field to add to the recovered `User`.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User)]
#[stash(context(
    prefix = "users",
    encrypt(caller = u64),
    decrypt(field = "scope")
))]
struct StoredScopeUser {
    #[stash(from_context)]
    scope: u64,
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_2() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_user();

    let stored: StoredScopeUser = user
        .encrypt_into_with_context(&keyset, 7_u64)
        .await?;
    assert_eq!(stored.scope, 7);
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from(loaded, &cipher).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

Logical context remains `7_u64`. It is stored once, not appended a second time
on decrypt. This generalizes the existing caller-supplied-and-stored case to
the field-by-field layout.

## 3. Plaintext field as context, no cleartext context stored

The encrypt selector reads `User.id`; no argument is needed. The output's
`id` is encrypted, so it cannot supply the context required to open itself.
The reader obtains the id from its external record lookup.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User)]
#[stash(context(
    prefix = "users",
    encrypt(field = "id"),
    decrypt(caller = u64)
))]
struct HiddenIdUser {
    id: Ciphertext,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_3() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_user();
    let lookup_id = user.id;

    let stored: HiddenIdUser = user.encrypt_into(&keyset).await?;
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from_with_context(loaded, &cipher, lookup_id).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

Both directions construct `R = 42_u64`. Supplying a different id fails to
open the encrypted fields. The id is not dropped or defaulted when rebuilding
`User`; its encrypted copy is opened using the externally supplied context.

## 4. Plaintext field as context, stored as the corresponding output field

This is the natural ID-bound form of workflow example 2. The context selector
and the passthrough annotation have separate jobs: select `id`, and copy it.
It uses the common-field shorthand, equivalent to the explicit pair of
directional selectors introduced above.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User)]
#[stash(context(prefix = "users", field = "id"))]
struct IdBoundUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_4() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_user();

    let stored: IdBoundUser = user.encrypt_into(&keyset).await?;
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from(loaded, &cipher).await?;
    assert_eq!(restored, user);

    // Alternatively, require the stored context to match the lookup's id.
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from_with_context(
        loaded,
        &cipher,
        NonEmpty::from(user.id),
    )
    .await?;
    assert_eq!(restored, user);
    Ok(())
}
```

The second decrypt call uses the `ExpectedContext<u64>` conversion. It checks
the stored id instead of constructing `(stored_id, expected_id)`. Changing
`id` alone breaks decryption; moving an entire consistent record is detected
only when the reader supplies the expected id (or another placement check).
`created_at` remains ordinary unauthenticated passthrough metadata.

## 5. Several plaintext fields as context, stored in separate fields

Add a tenant id to the input. The context is the ordered pair `(tenant_id, id)`.
The output renames `id` to `user_id` to demonstrate why direction-specific
field selectors are useful. No duplicate context metadata field is needed.

```rust
#[derive(Debug, PartialEq)]
struct TenantUser {
    tenant_id: u64,
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

fn sample_tenant_user() -> TenantUser {
    TenantUser {
        tenant_id: 7,
        id: 42,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
        created_at: 1_700_000_000,
    }
}

#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = TenantUser)]
#[stash(context(
    prefix = "users",
    encrypt(tuple(field = "tenant_id", field = "id")),
    decrypt(tuple(field = "tenant_id", field = "user_id"))
))]
struct TenantBoundUser {
    #[stash(passthrough)]
    tenant_id: u64,
    #[stash(passthrough, from = "id")]
    user_id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_5() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_tenant_user();

    let stored: TenantBoundUser = user.encrypt_into(&keyset).await?;
    let loaded = store_and_reload(&stored)?;
    let restored = TenantUser::decrypt_from(loaded, &cipher).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

Both directions construct `(7_u64, 42_u64)`. Rust field order does not choose
the context order: the selector does. A Serde wire rename also does not change
the selector; it names Rust fields, not serialized property names.

## 6. Plaintext field plus caller argument, store the combined context

Here `R = (User.id, caller_scope)`. `binding` stores that complete pair. The
original id is also retained as ciphertext so `User` can be reconstructed
without adding a new rule that maps pieces of metadata into plaintext fields.
That deliberately redundant representation keeps this example focused on
context composition rather than projection conveniences.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User)]
#[stash(context(
    prefix = "users",
    encrypt(tuple(field = "id", caller = u64)),
    decrypt(field = "binding")
))]
struct StoredCombinedUser {
    #[stash(from_context)]
    binding: (u64, u64),
    id: Ciphertext,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_6() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_user();

    let stored: StoredCombinedUser = user
        .encrypt_into_with_context(&keyset, 7_u64)
        .await?;
    assert_eq!(stored.binding, (42, 7));
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from(loaded, &cipher).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

The encryption function accepts only the caller-supplied component (`7`), not
the pair the derive can construct itself. A checked decrypt would expect the
whole reconstructed pair `(42, 7)`, not just that caller component.

## 7. Plaintext field plus caller argument, store only the field component

Store `id` as a normal field, but keep the external scope out of the output.
Decryption combines the stored id with the scope supplied by the reader.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User)]
#[stash(context(
    prefix = "users",
    encrypt(tuple(field = "id", caller = u64)),
    decrypt(tuple(field = "id", caller = u64))
))]
struct PartiallyStoredUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_7() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_user();
    let scope = 7_u64;

    let stored: PartiallyStoredUser = user
        .encrypt_into_with_context(&keyset, scope)
        .await?;
    let loaded = store_and_reload(&stored)?;
    let restored = User::decrypt_from_with_context(loaded, &cipher, scope).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

This also constructs `(42_u64, 7_u64)` in both directions. It shows why
"stored context" cannot always be represented as a single yes/no flag:
some components may be stored and others supplied externally. A separate
expected-id check can be performed against `loaded.id` before opening when
the application also needs to assert the record's destination.

## 8. Several plaintext fields as context, keep neither component in cleartext

The encrypt side obtains `(tenant_id, id)` from the source. The reader supplies
the complete pair from outside the encrypted record; both source fields are
recovered from ciphertext after that context has been established.

```rust
#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = TenantUser)]
#[stash(context(
    prefix = "users",
    encrypt(tuple(field = "tenant_id", field = "id")),
    decrypt(caller = (u64, u64))
))]
struct HiddenTenantUser {
    tenant_id: Ciphertext,
    id: Ciphertext,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

async fn example_8() -> Result<()> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();
    let user = sample_tenant_user();
    let lookup_context = (user.tenant_id, user.id);

    let stored: HiddenTenantUser = user.encrypt_into(&keyset).await?;
    let loaded = store_and_reload(&stored)?;
    let restored =
        TenantUser::decrypt_from_with_context(loaded, &cipher, lookup_context).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

This is a new typed selector contract. It does not mean flattening the pair
into text, or treating separately chained extensions as interchangeable with
one tuple-valued argument.

## Candidate program entry point

```rust
#[tokio::main]
async fn main() -> Result<()> {
    example_0().await?;
    example_1().await?;
    example_2().await?;
    example_3().await?;
    example_4().await?;
    example_5().await?;
    example_6().await?;
    example_7().await?;
    example_8().await?;
    Ok(())
}
```

## Consequences for the traits and derive

The logical context `R` is not always the value a caller passes. For example:

| Scenario | Logical `R` | Caller input on encrypt | Caller input on decrypt |
| --- | --- | --- | --- |
| 1 | `u64` | Required `u64` | Required `u64` |
| 2 | `u64` | Required `u64` | Optional expectation of `u64` |
| 3 | `u64` | None | Required `u64` |
| 4 | `u64` | None | Optional expectation of `u64` |
| 6 | `(u64, u64)` | Required `u64` component | Optional expectation of the whole pair |
| 7 | `(u64, u64)` | Required `u64` component | Required `u64` component |
| 8 | `(u64, u64)` | None | Required pair |

Today `EncryptFrom<S>::Context` and `DecryptInto<P>::Context` already belong
to separate traits and can differ. They describe the input the caller needs
to supply, not necessarily the final context used by every operation. That
distinction should be explicit in documentation; `ContextInput` might be a
clearer name, but a rename is not decided here.

No-caller-input selectors can expose a defaultable input, such as `()`, to
support `encrypt_into`. Stored-context decrypt uses the existing
`ExpectedContext<R>` idea. Required caller selectors must remain required
even if their Rust type implements `Default`: a required `u64` must not
silently become zero merely because `u64: Default`.

That exposes a real constraint in today's convenience methods, whose only
test is `Context: Default`. An implementation of this proposal would need
a non-defaultable `RequiredContext<T>` input (with an ergonomic conversion
from `T`), or a separate trait capability controlling context-free calls.
The examples show bare caller values at call sites, but do not assume that
the associated input type can be bare `u64`. Choose that mechanism before
claiming the directional API enforces required inputs.

The current public `Encryption` constructors must also gain or expose the
core-owned source-selection machinery needed by the derive. Existing plan
context fields demonstrate source-dependent context, but are label-based,
carry the field, and use different composition rules. They are not already
an implementation of this proposal's general typed, optionally stored `R`.

## Rules the implementation should enforce

- Selectors for both directions must produce the same context type and
  ordered structure. Different Rust field names are fine; different values
  or grouping are not a supported way to encrypt and decrypt one record.
- Resolve field names and types at compile time. A decrypt selector cannot
  read an encrypted field to obtain the context needed to decrypt it.
- A `from_context` field is cleartext output metadata with the logical
  context's type. It cannot also be encrypted, defaulted, or independently
  copied from an unrelated source. Ordinary passthrough fields do not
  become context merely because their names are `id` or `tenant_id`.
- Extra metadata is not invented as a plaintext field during recovery.
  Every original plaintext field must have a defined recovery path; no
  silent omission or defaulting to compensate for a context-only source.
- Check supplied expectations before key retrieval where possible. A
  context value read from storage remains untrusted until encrypted fields
  authenticate under it. An expectation check alone is not authentication.
- If a selected source value is duplicated in stored context metadata and
  in a separately recovered plaintext field, validate their agreement
  before returning the reconstructed object. Do not return a different id
  from the one the encrypted fields were bound to.
- Stored context should be required in the serialized schema; a missing
  field must not silently fall back to a default context. Empty-context
  policy must be explicit and retain the current nonempty target rule.
- For indexed targets, the selected context also scopes their terms unless
  a future API explicitly separates index context from ciphertext context.
  A row-specific id therefore changes search semantics; these examples
  concern ciphertext layouts and do not silently promise cross-row queries.

Required tests include storage round trips for every scenario, missing
required arguments, wrong expected values, altered stored context, tuple
reordering/regrouping, renamed source/output fields, and attempted circular
decrypt dependencies. Same-typed field swaps may evade a type check, so
round-trip and mismatch tests remain necessary even with typed selectors.

## Alternatives worth comparing

1. **Field-level `context(encrypt, decrypt)` flags.** Concise for one id,
   but references the output declaration while the encrypt source lives
   elsewhere, leaves multi-field order implicit, and cannot readily describe
   caller-plus-field composition. Prefer explicit container selectors first.
2. **One `context = expression` callback.** Flexible, but hides dependencies,
   makes reverse reconstruction and cycle checks harder, and encourages
   arbitrary application code in the declaration. Keep simple declarative
   selectors as the initial surface.
3. **A typed context object with a dedicated derive.** Could reduce repetition
   for large composite contexts and carry a stronger encoding contract.
   Consider it after the scalar/tuple cases establish the desired semantics.

The recommendation is the directional selector plus independent storage
model, not a commitment to every spelling shown here. In particular,
`from_context`, `prefix`, the tuple notation, and how required inputs are
represented remain review choices.

## Evidence and validation

Current behavior was checked in
[context types](../../packages/stack-encrypt/src/target/context.rs),
[target traits and convenience methods](../../packages/stack-encrypt/src/target/operations.rs),
[derive validation](../../packages/stack-encrypt-derive/src/shape.rs), and
[plan context fields](../../packages/stack-encrypt/src/plan/build.rs).
The directional nesting is inspired by Serde, not provided by Serde.

These are candidate API examples. Syntax/link checks do not establish macro
support, type correctness, or encryption behavior. No live encryption or
database tests are claimed, and no library implementation is changed.

Validation completed: `rustfmt` parsed the combined nine-scenario candidate
program and the introductory fragments (wrapped as Rust items), using edition
2024. Local links, Markdown fences, and trailing whitespace were checked in
this document and both companion documents. No proposed macro was expanded
or typechecked.
