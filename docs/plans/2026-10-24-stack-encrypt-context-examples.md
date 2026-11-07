# Context sources and storage: directional API examples

Date: 24 October 2026. This design exploration goes with the
[API review log](2026-10-24-stack-encrypt-api-review.md) and the
[complete public workflow examples](2026-10-24-stack-encrypt-public-examples.md).

**Everything introduced here is proposed syntax, not an implemented API.**
None of the code below compiles against Stack Encrypt today.

## Decisions on 7 November 2026

The [API plan](2026-10-24-stack-encrypt-api-plan.md#context-from-fields-and-from-the-caller)
records three decisions that change this document. The scenarios stay as
the acceptance matrix for the Rust API. The prose and the attribute
spellings will be rewritten after the plan builder's entry points are
settled.

- **The plan builder is the one mechanism.** The derive's attributes lower
  to it, as the dynamic grammar does. A field's context comes from a
  literal, from a row field carried unsealed, or from the caller on every
  call. The directional selectors `encrypt(field = ..)` and
  `decrypt(caller = ..)` do not survive as a mechanism of their own.
- **Scenarios 3 and 8 are removed.** Each seals a value that is also the
  context of another field. A reader must know the plaintext before it
  can open anything, so the sealed copy protects nothing. A value the
  caller already knows is a caller-supplied part on both sides. It is
  not stored.
- **Scenario 7 stays, renamed.** A caller-supplied part that is never
  stored, such as a host or application ID, means the data opens only
  where that part is known. The type name `PartiallyStoredUser` is wrong:
  the record is fully stored, and only part of its context is not.
- **Parts are separate and ordered.** Refinements, then binding parts.
  "Extension" is now "refinement". A binding part is a new kind. See [Two
  scopes of one
  context](2026-10-24-stack-encrypt-api-plan.md#two-scopes-of-one-context).

## Implementation status on 7 November 2026

This document was checked against `next` at commit `e4990e49b`. The
directional selectors are not implemented. These parts of the model are
now in the code:

- **Required input.** Pull request #1404 adds `RequiredContext`,
  `NoCallerContext`, and `OptionalContext` for the owned API. A required
  `u64` stays required, even though `u64` implements `Default`.
- **Composition.** Pull request #1491 makes repeated Rust extensions append
  in order. A grouped extension stays one part. This matches the
  composition rule below.
- **Conformance.** Pull request #1491 adds shared Rust and Go cases for a
  base with extensions, for stored-context expectations, and for altered
  context. The nine scenarios below are not among those cases.

Still open, or in progress:

- `ContextExtension` and `ExpectedContext` as caller inputs. Pull request
  #1504 adds them, and is in progress.
- `context(...)`, `from_context`, `prefix`, and `tuple(...)`. No pull
  request adds them.

From 7 November 2026, the stored format of Go `v0.1.0-rc.3` must not
break. So a new selector must produce the same context bytes as rc.3 for
data that rc.3 can write. See the [API
plan](2026-10-24-stack-encrypt-api-plan.md#the-stored-format-stays-compatible-with-go-rc3).

This document
compares what happens to encryption context in each useful combination of
context source and context storage. That comparison comes before anyone
chooses attributes or changes traits. The `Ciphertext` and `passthrough`
proposals come from the workflow draft. The workflow draft is the complete
public workflow examples document linked above.

## Terms used in this document

These terms appear throughout. Each one is also explained where it first
matters:

- **Encryption context**, or context, is data that a ciphertext is tied
  to, such as a column name or a row ID. Decryption needs the same context.
  The context also scopes a field's search terms. See [Context and
  AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad).
- **AAD** means additional authenticated data. Encryption checks it for one ciphertext, but does not encrypt it. Stack Encrypt builds it from
  the context.
- **Static prefix** is the fixed string in the declaration, such as
  `"users"`. Together with the field name it forms a field's static base.
- **Logical row context**, written `R`, is the part of the context that
  changes from record to record, such as a user id.
- **Effective context** is the complete context one field is encrypted
  under: its static base combined with `R`.
- **Selector** is a declaration inside `context(...)` that says where to
  get `R`, for one direction or for both.
- **Caller argument** is a context value the application passes to a
  `*_with_context` method, rather than one read from a record.
- **Passthrough field** is an output field copied in cleartext from the
  input, with `#[stash(passthrough)]`. A passthrough field is not encrypted
  and not authenticated.
- **`from_context` field** is an output field that stores the computed `R`
  in cleartext, so that decryption can read it back.
- **Caller extension** is an existing feature of the simple static form.
  The caller adds an extra context value to the declared static context.
- **Keyset** is a set of encryption keys held in ZeroKMS, CipherStash's key
  management service. `cipher.default_keyset()` chooses which keyset
  encrypts.
- **The derive** means the `EncryptFrom` and `DecryptInto` derive macros in
  `packages/stack-encrypt-derive`.

## Recommendation: directional sources, separate storage

Name each direction, and say for each one where to get context. Store
the context with a separate field annotation.

The nested direction style comes from Serde. Serde's `rename` attribute can
contain separate names for serialisation and deserialisation. See
[Serde's field attributes](https://serde.rs/field-attrs.html).

For encryption, the direction names say **where to get context**:

```rust
#[stash(context(
    prefix = "users",
    encrypt(field = "id"),
    decrypt(field = "id")
))]
```

The two `field` selectors refer to different objects. On encrypt, the
selector reads the plaintext input. On decrypt, it reads the encrypted
input. Both must produce the same typed context value.

Unlike the two names in a Serde rename, the two selectors are not
independent cryptographic names. If the context value or its shape differs
between the two directions, decryption fails.

Both directions often use the same Rust field name. For that case, the
recommended shorthand is:

```rust
#[stash(context(prefix = "users", field = "id"))]
```

This shorthand expands exactly to
`encrypt(field = "id"), decrypt(field = "id")`. It still reads two
different objects: the plaintext input on encrypt, and the encrypted input
on decrypt. The shorthand does not copy or store the field by itself. The
output layout must make that value available, normally with passthrough.
Use the explicit directional form when the names or sources differ.

To **store the computed context**, use a separate field annotation. This is
needed only when ordinary passthrough fields do not already contain the
context value:

```rust
#[stash(from_context)]
scope: u64,
```

A `from_context` field is an output metadata field filled from the
computed logical context. It does not choose where the context comes from.
A passthrough source field can already contain the context value. In that
case, no `from_context` field is needed. This proposal adds no new
source-side encryption methods and no public `encrypt_as` entry point.

These names are better than bare `context(in)` and `context(out)`. Each of
those terms could mean any of three things:

- an operation direction;
- an input object or an output object;
- storing a value.

The names `encrypt`, `decrypt`, and `from_context` give those three roles
separate names.

## Proposed vocabulary and semantics

The table lists each proposed form inside `context(...)` and what it means.

| Syntax inside `context(...)` | Meaning |
| --- | --- |
| `prefix = "users"` | Static base for this layout's field contexts |
| `field = "id"` | Shorthand for both `encrypt(field = "id")` and `decrypt(field = "id")` |
| `encrypt(caller = u64)` | Get the logical context from a required `u64` argument |
| `encrypt(field = "id")` | Get it from the plaintext input's `id` |
| `decrypt(caller = u64)` | Get it from a required `u64` argument on decrypt |
| `decrypt(field = "scope")` | Get it from the encrypted input's cleartext `scope` |
| `encrypt(tuple(field = "tenant_id", field = "id"))` | Build one ordered, typed pair from plaintext fields |
| `decrypt(tuple(field = "id", caller = u64))` | Build one pair from a stored field and the decrypt argument |

`tuple(...)` is a declarative selector. It is not a Rust expression or a
function that gets access to keys. A `tuple(...)` can contain another
`tuple(...)`.

The derive resolves `field` names at compile time. The first design
supports direct fields only, not arbitrary paths or callbacks. Each
direction has at most one caller argument selector. When that argument
needs several values, make it a tuple or a typed context object.

A declaration uses either the shared `field` shorthand, or both explicit
directional selectors. For the initial API, the derive rejects a mix of the
shorthand and directional selectors. Rejecting the mix avoids inventing
precedence rules, and keeps the expansion predictable. A record whose names
differ between directions uses the explicit form.

`context = "users"`
remains the existing simple spelling for a static prefix with optional
caller extensions. Scenario 0 uses it.

### Composition rule

Call the logical row context `R`. A field named `name` has the static base
`B = ("users", "name")`. Its effective context is `(B, R)`. With only
a static prefix and no extension, the effective context is `B`, not
`(B, ())`.

The selector's result is **one structured value**. A pair
`(tenant_id, id)` produces `(("users", "name"), (tenant_id, id))`, not
`((("users", "name"), tenant_id), id)`. A `from_context` field stores `R`,
not the effective context. The effective context differs from field to
field. Static prefixes and field identities are rebuilt from the
declaration.

The names in this proposal do not change existing byte encodings. When new
selectors are mapped onto the existing context code, they must preserve
types, order, grouping, and descriptor rendering. A new explicit selector
is a new declaration. It must not silently reinterpret data that is already
stored.

### Storage and expected context

Sometimes stored fields contain all of `R`. Then the default decrypt call
rebuilds `R` from those fields. The caller can also supply an expected `R`
through the existing `ExpectedContext<R>` pattern. Decryption then checks
that the two are equal, and uses the stored value. That expected value is
**not another extension**.

A decrypt selector can need a caller argument. That argument is then
required to build `R`, and no call without a context is available. It is
not a check of an expected value against context the record already
contains in full.

A future caller could need both a required input and a separate check of
the assembled `R`. That caller would use a distinct checked-context input
or a named API. Do not make one unlabelled argument mean both. This
proposal does not include that combined-check API. Scenario 7 shows where
the need arises.

## Scenario matrix

Each scenario combines one context source with one way of storing it. The
table shows where each scenario gets and stores the context.

| Scenario | Encrypt gets context from | Context available in stored output | Decrypt gets context from |
| ---: | --- | --- | --- |
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
before decryption. Scenarios 3 and 8 keep encrypted copies so that
decryption can recover the complete plaintext object. Callers still need to
supply the context separately.

## Shared code for the examples

Each scenario defines an output type and an async function. Together, this
prelude, the scenario blocks, and the final `main` form one candidate
program. Every example stores its output in a real file and reads it back
through the same helper. So no example depends on a context value hidden
inside an in-memory handle. All the examples use proposed APIs, so they
cannot be typechecked against Stack yet.

The dependencies match the workflow draft: Stack Encrypt, Serde with
derives, serde_json, tempfile, and Tokio. Once these APIs exist, the
examples need ZeroKMS credentials. In the caller examples, `scope = 7` is
external application context. It is not a keyset selector or an
authorisation credential.

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

This example shows the baseline: a static prefix and nothing else. There
is no row context to store or supply. The example keeps the existing
static-context form, and uses the proposed passthrough support.

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

With this shorthand, caller extensions stay available, as previously
agreed. Encrypt and decrypt must receive the same extension. The remaining
examples use explicit directional selectors. Their argument requirements
come from those selectors alone. No implicit extension is added on top.

## 1. Caller context, not stored

This example shows a context that the caller supplies and the output does
not store. `scope` is absent from the output, so the caller must provide it
again on decrypt. The plaintext `id` in this layout has nothing to do with
the chosen context source.

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

Logical context: `7_u64`. Effective context for `name`:
`(("users", "name"), 7_u64)`.

## 2. Caller context, stored in an output metadata field

This example shows a caller-supplied context that the output stores, so
decrypt needs no argument. The source is still the function argument. The
`from_context` field stores its value, and the decrypt selector explicitly
chooses that stored field. `scope` is output metadata. It is not a field to
add to the recovered `User`.

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

The logical context is still `7_u64`. The output stores it once, and
decrypt does not append it a second time. This example extends the
existing case, where the caller supplies the context and it is stored, to
the field-by-field layout.

## 3. Plaintext field as context, no cleartext context stored

This example shows a context read from a plaintext field that is then
encrypted, so the output has no cleartext copy. The encrypt selector reads
`User.id`, so encrypt needs no argument. The output's `id` is encrypted. An
encrypted `id` cannot supply the context needed to decrypt itself. The
reader gets the id from its own record lookup, outside the record.

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

Both directions build `R = 42_u64`. If the reader supplies a different id,
the encrypted fields fail to decrypt. Rebuilding `User` does not drop the
id or use a default. Decryption opens the encrypted copy of the id with
the context the reader supplied.

## 4. Plaintext field as context, stored as the corresponding output field

This example shows a context read from a plaintext field and stored as a
passthrough copy of the same field. It is the obvious id-bound form of
workflow example 2. The context selector and the passthrough annotation
have separate jobs: the selector chooses `id`, and passthrough copies it.
The example uses the shared `field` shorthand. That shorthand is the same
as the explicit pair of directional selectors introduced above.

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

The second decrypt call uses the `ExpectedContext<u64>` conversion. That
call checks the stored id. It does not build `(stored_id, expected_id)`.

Changing `id` alone breaks decryption. Moving a whole consistent record is
detected only if the reader supplies the expected id, or checks placement
another way. `created_at` stays ordinary passthrough metadata. Passthrough
metadata is not authenticated.

## 5. Several plaintext fields as context, stored in separate fields

This example shows a context built from two plaintext fields, both stored
as passthrough fields. The input gains a tenant id, and the context is the
ordered pair `(tenant_id, id)`. The output renames `id` to `user_id`. The
rename shows why separate field selectors for each direction are useful.
No extra context metadata field is needed.

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

Both directions build `(7_u64, 42_u64)`. The selector sets the order of
the context, not the order of the Rust fields. A Serde rename of the
stored property also leaves the selector unchanged. Selectors name Rust
fields, not serialised property names.

## 6. Plaintext field plus caller argument, store the combined context

This example shows a context built from a plaintext field and a caller
argument, with the whole pair stored. Here
`R = (User.id, caller_scope)`, and the `binding` field stores that
complete pair. The output also keeps the original id as ciphertext, so
that decryption can rebuild `User`. Without that copy, the derive would
need a new rule that maps pieces of metadata into plaintext fields. The
id is stored twice on purpose, so that this example stays about how the
context is put together, not about mapping metadata to fields.

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

The encryption function accepts only the part the caller supplies (`7`).
It does not accept the whole pair, because the derive can build the pair
itself. A checked decrypt would expect the whole rebuilt pair `(42, 7)`,
not only the caller's part.

## 7. Plaintext field plus caller argument, store only the field component

This example shows a context built from a plaintext field and a caller
argument, with only the field stored. The output stores `id` as a normal
passthrough field, and leaves the external scope out. Decryption combines
the stored id with the scope the reader supplies.

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

This example also builds `(42_u64, 7_u64)` in both directions. It shows
why one yes-or-no flag cannot always describe whether context is stored.
Some parts may be stored, and others supplied from outside the record.
The application can also need to check which record it has. If so, it can
compare `loaded.id` with an expected id before decrypting.

## 8. Several plaintext fields as context, keep neither component in cleartext

This example shows a context built from two plaintext fields, with neither
stored in cleartext. The encrypt side gets `(tenant_id, id)` from the
source. The reader supplies the complete pair from outside the encrypted
record. Once that context is supplied, decryption recovers both source
fields from their ciphertexts.

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

This is a new contract for a typed selector. It does not mean flattening
the pair into text. It also does not make separately chained extensions
interchangeable with one argument whose value is a tuple.

## Candidate program entry point

This `main` runs all nine scenarios in order.

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

The logical context `R` is not always the value a caller passes. The table
compares `R` with the caller's input in the scenarios that have a row
context:

| Scenario | Logical `R` | Caller input on encrypt | Caller input on decrypt |
| ---: | --- | --- | --- |
| 1 | `u64` | Required `u64` | Required `u64` |
| 2 | `u64` | Required `u64` | Optional expectation of `u64` |
| 3 | `u64` | None | Required `u64` |
| 4 | `u64` | None | Optional expectation of `u64` |
| 6 | `(u64, u64)` | Required `u64` component | Optional expectation of the whole pair |
| 7 | `(u64, u64)` | Required `u64` component | Required `u64` component |
| 8 | `(u64, u64)` | None | Required pair |

Today, `EncryptFrom<S>::Context` already belongs to a different trait from
`DecryptInto<P>::Context`. The two types can differ.

Each `Context` type describes the input the caller needs to supply. That
input is not always the final context every operation uses. The documentation should state that difference. The name
`ContextInput` might be clearer, but this document does not decide on a
rename.

To support `encrypt_into`, a selector that needs no caller input can
expose an input that has a default, such as `()`. A decrypt that reads
stored context uses the existing `ExpectedContext<R>` idea. A required
caller selector must stay required, even if its Rust type implements
`Default`. A required `u64` must not silently become zero only because
`u64: Default`.

That rule exposed a real limit in the convenience methods of 24 October
2026. Their only test was `Context: Default`. Since #1404, the owned
methods use the explicit capabilities `AllowsNoContext` and
`AcceptsContext` instead. The structural methods in `target::legacy` still
use `Default`. An implementation of this proposal would need
one of two things:

- a `RequiredContext<T>` input that has no default, with an easy
  conversion from `T`;
- a separate trait capability that controls calls without a context.

The examples pass bare caller values at call sites. They do not assume
that the associated input type can be a bare `u64`. Choose that mechanism
before claiming the directional API enforces required inputs.

The current public `Encryption` constructors must also gain or expose the
source-selection code the derive needs, owned by the core crate.

Plan context fields are the existing context fields of the plan builder,
in `packages/stack-encrypt/src/plan/build.rs`. They already show context
that depends on the source. But plan context fields are based on labels,
carry the field, and use different composition rules. So they do not
already implement this proposal's general `R`: a typed value that can be
stored.

## Rules the implementation should enforce

The implementation should enforce these rules:

- Selectors for both directions must produce the same context type and
  ordered structure. Different Rust field names are fine. Different values
  or grouping are not a supported way to encrypt and decrypt one record.
- Resolve field names and types at compile time. A decrypt selector cannot
  read an encrypted field to get the context needed to decrypt it.
- A `from_context` field is cleartext output metadata with the logical
  context's type. It cannot also be encrypted, set to a default, or copied
  separately from an unrelated source. An ordinary passthrough field does
  not become context only because its name is `id` or `tenant_id`.
- Recovery does not invent extra metadata as a plaintext field. Every
  original plaintext field must have a defined way to be recovered. No
  field is silently left out, or set to a default, because a source was
  used only for context.
- Check supplied expectations before fetching keys, where possible. A
  context value read from storage stays untrusted until the encrypted
  fields authenticate under it. An expectation check alone is not
  authentication.
- A selected source value can appear both in stored context metadata and
  in a separately recovered plaintext field. If so, check that the two
  agree before returning the rebuilt object. Never return an id different
  from the one the encrypted fields were bound to.
- Stored context should be required in the serialised schema. A missing
  field must not silently fall back to a default context. The policy for
  empty context must be explicit. That policy must keep the current rule
  that a target's context is nonempty.
- An indexed target is a field that also produces search index terms. For
  an indexed target, the selected context also scopes those terms, unless
  a future API explicitly separates index context from ciphertext
  context. So a row-specific id changes how search works. These
  examples are about ciphertext layouts. They do not silently promise
  queries that match across rows.

The required tests are:

- storage round trips for every scenario;
- missing required arguments;
- wrong expected values;
- altered stored context;
- reordered or regrouped tuples;
- renamed source or output fields;
- attempts to make decryption depend on its own output in a circle.

Two fields of the same type can be swapped without failing a type check.
So round-trip and mismatch tests are still needed, even with typed
selectors.

## Alternatives worth comparing

1. **Field-level `context(encrypt, decrypt)` flags.** These are concise for
   one id. But they refer to the output declaration, while the encrypt
   source is declared elsewhere. They leave the order of several fields
   unstated, and cannot easily describe a context built from a caller
   argument and a field. Prefer explicit selectors on the container first.
2. **One `context = expression` callback.** This is flexible, but it hides
   dependencies. It makes rebuilding the context in reverse harder, and
   makes cycles harder to detect. It also encourages arbitrary application
   code in the declaration. Keep simple declarative selectors as the
   initial API.
3. **A typed context object with a dedicated derive.** This could reduce
   repetition for large composite contexts, and give a stronger encoding
   contract. Consider it once the single-value and tuple cases have settled
   the intended behaviour.

The recommendation is the model of directional selectors with separate
storage. It is not a commitment to every spelling shown here. In
particular, these remain choices for review: `from_context`, `prefix`, the
tuple notation, and how required inputs are represented.

## Evidence and validation

The current behaviour was checked in these files:

- [context types](../../packages/stack-encrypt/src/target/context.rs);
- [target traits and convenience methods](../../packages/stack-encrypt/src/target/operations.rs);
- [derive validation](../../packages/stack-encrypt-derive/src/shape.rs);
- [plan context fields](../../packages/stack-encrypt/src/plan/build.rs).

Serde inspired the directional nesting, but Serde does not provide it.

These are candidate API examples. Checks of syntax and links do not show
that the macros support them, that the types are correct, or that
encryption works as described. This document claims no live encryption
or database tests, and changes no library code.

The following validation was completed. `rustfmt` parsed the combined
candidate program for the nine scenarios, using edition 2024. It also
parsed the introductory fragments, wrapped as Rust items. Local links,
Markdown fences, and trailing whitespace were checked in this document and
both companion documents. No proposed macro was expanded or typechecked.
