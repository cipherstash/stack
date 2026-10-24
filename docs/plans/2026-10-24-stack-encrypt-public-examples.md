# Stack Encrypt: complete public API examples for review

Date: 2026-10-24. Companion to the
[API review log](2026-10-24-stack-encrypt-api-review.md).
The separate [context examples](2026-10-24-stack-encrypt-context-examples.md)
explore directional source selection, storing context, and decrypt inputs
across nine scenarios. Their attributes are proposals, not implemented APIs.

This document tests the proposed public API against three complete workflows:
encrypt, persist, load, and decrypt a user; the searchable workflow also
constructs and applies a query. It is an API design draft, not documentation
for a released version. The examples deliberately leave plans and operation
descriptions out of the application code.

Each main example is a separate program, with all imports and types shown.
They use the same user fields and synthetic data. `created_at` is an `i64`
Unix timestamp in seconds so that date-library configuration does not distract
from the encryption API. The storage files live in a temporary directory and
are removed when the program exits. Files stand in for a database boundary;
the examples really encode, write, read, and decode their stored forms.

## What is agreed, and what these examples propose

| Surface | Status in this review |
| --- | --- |
| `keyset.encrypt(value)` and `encrypt_with_context(value, context)` | Agreed direction; current code still has the two-argument `encrypt` method |
| `value.encrypt_into(&keyset)` and `encrypt_into_with_context` | Retained existing entry points |
| No public `encrypt_as` in these examples | Agreed direction; current implementation still exposes it |
| `#[stash(passthrough)]` on output fields | Accepted in principle; needs implementation on both encrypt and decrypt derives |
| A fixed context on a scalar output derive | Agreed direction; not required by these particular examples |
| `OpaqueBlob<T>` | Agreed wrapper direction; provisional name. Requests whole-value serialization and one encrypted leaf, using a library-owned codec |
| `Ciphertext` | Proposed name for an opaque single-value ciphertext; **not** today's `StackCipherText` or `CipherText` enum |
| `Ciphertext::to_bytes` / `from_bytes` | Proposed direct access to the existing canonical sealed-leaf encoding, without node extraction |
| `Ciphertext: Serialize + Deserialize` | Proposed storage contract: Base64 of the canonical bytes for human-readable serializers, bytes for binary serializers |
| `Ciphertext` as an encryption/decryption target | Proposed scalar target, including support for `String` and `Vec<u8>`; does not silently flatten a struct into a blob |
| Decrypt into `OpaqueBlob<T>`, then `into_inner()` | Proposed symmetric decoding path; returns the original application value after authentication and decoding |
| `cipher.decrypt_with_context` | Proposed companion to `encrypt_with_context`; ordinary decrypt naming remains a review decision |
| `User::decrypt_from` / `decrypt_from_with_context` | Existing `DecryptFrom` extension conveniences, retained here pending the decrypt naming discussion |
| `SearchableEmail` in example 3 | Application-defined target composed from ciphertext and an existing `EqualityTerm` |

The first three Rust blocks use proposed `OpaqueBlob`, `Ciphertext`, and/or
passthrough APIs. They are complete candidate programs, not programs claimed
to compile against today's crate. The names and contracts above remain
subject to review where marked proposed or provisional.

The proposed opaque ciphertext is intentionally untyped: the decrypt call's
expected type selects decoding. A typed wrapper remains an open alternative.
Its byte decoder parses a stored envelope; authentication happens on decrypt.
For a derived field it must preserve the existing context and leaf encoding,
not introduce a new cryptographic format just to improve ergonomics.

The trait name `DecryptFrom` is somewhat surprising: it supplies the
convenience functions, while `#[derive(DecryptInto)]` describes how an
encrypted output recovers plaintext. These examples keep that existing
distinction visible rather than silently redesigning it.

## Setup shared by the programs

The proposed programs use `stack-encrypt` with its default `http` feature,
`serde` with `derive`, `serde_json`, `tempfile`, and `tokio` with `macros` and
`rt-multi-thread`. No published version currently supplies all proposed APIs,
so this draft does not give a misleading installable Cargo manifest.

`StackCipher::new()` uses the configured ZeroKMS credentials: a CLI login or
`CS_CLIENT_ID`, `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`, and `CS_WORKSPACE_CRN`.
The second client in each program represents a later reader using the same
authorized configuration. The default keyset is selected for brevity; an
already-selected tenant keyset can be used in its place.

Decryption uses the client because the sealed value carries its keyset id.
It still requires access to the corresponding keys and the correct context.
The examples do not depend on in-memory fake keys surviving a reload.

## 1. Encrypt the whole user through an explicit blob wrapper

**Intent:** store one encrypted document. All four fields, including the ID
and creation time, are inside one encrypted serialization. There are no
independently readable fields or search terms in the stored ciphertext.

`OpaqueBlob::new(user)` explicitly requests that treatment. Stack owns the
serialization and matching deserialization, rather than requiring every
application to select and invoke a codec. The proposed wrapper owns the input;
`new` only wraps it, and serialization errors surface from the encryption
operation. The context identifies the application's document schema and binds
this document to an externally known record id.

For this draft the wrapper accepts Serde `Serialize` on write and
`DeserializeOwned` on read. That input-trait choice is provisional: it does
not claim that arbitrary Serde implementations can satisfy a constant-time
contract. The initial wrapper has one library-selected, versioned binary
codec, not a caller-selected codec parameter. Selecting and specifying that
codec remains implementation/design work; no particular binary format is
claimed to be implemented or constant-time here.

```rust
use serde::{Deserialize, Serialize};
use stack_encrypt::{nonempty, Ciphertext, OpaqueBlob, StackCipher};
use std::error::Error;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct User {
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let writer = StackCipher::new().await?;
    let keyset = writer.default_keyset();
    let expected_id = 42_u64; // Supplied by the application's record lookup.
    let user = User {
        id: expected_id,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
        created_at: 1_700_000_000,
    };

    let expected = user.clone(); // Retained only for the round-trip assertion.

    // The wrapper requests one blob and lets Stack handle serialization.
    let sealed: Ciphertext = keyset
        .encrypt_with_context(
            OpaqueBlob::new(user),
            nonempty!("user-document-v1").with(expected_id),
        )
        .await?;

    // Persist the complete ciphertext envelope as binary bytes.
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("user.ciphertext");
    std::fs::write(&path, sealed.to_bytes())?;

    // Later: reconstruct the ciphertext from storage using a new client.
    let reader = StackCipher::new().await?;
    let stored_bytes = std::fs::read(&path)?;
    let loaded = Ciphertext::from_bytes(&stored_bytes)?;

    // Stack authenticates/decrypts first, then decodes the blob into User.
    let opened: OpaqueBlob<User> = reader
        .decrypt_with_context(
            loaded,
            nonempty!("user-document-v1").with(expected_id),
        )
        .await?;
    let restored = opened.into_inner();
    assert_eq!(restored, expected);
    Ok(())
}
```

**What the API must guarantee:** the serialized bytes are one encrypted leaf
under one data key. The envelope contains the retrieval metadata, so the
caller never needs to save an IV or key tag separately. A different context
must fail to open it. Stack owns the matching encode/decode pair and its
compatibility contract. A blob-format discriminator and version must be
authenticated, for example inside the encrypted payload, so decoding does
not rely on guessing a codec or on unauthenticated format metadata. This
can reuse the canonical outer ciphertext envelope; the blob payload is a
new, explicit format rather than silently reinterpreting previously encrypted
raw bytes. Application schema evolution remains explicit: a codec version
does not automatically migrate changes to `User`.

**Without application context:** use `keyset.encrypt(OpaqueBlob::new(user))`
form. A matching no-context `reader.decrypt(loaded)` is proposed for symmetry;
it is not the signature of today's two-argument decrypt method. This document
uses explicit context in the full example so the saved format is unambiguous.

**Meaning of the wrapper:** `OpaqueBlob<User>` is the plaintext-side request
and the decoded value, not the stored ciphertext type. `Ciphertext` remains
the persisted envelope. `into_inner()` returns an ordinary `User`. The
wrapper does not by itself promise to zeroize arbitrary input/returned types;
the codec should keep temporary plaintext buffers in wipeable storage.
`#[derive(Encrypt)]` on `User` currently means a structural ciphertext tree
and is not a substitute for wrapping the value as one blob.

### Timing contract to investigate

The desired property is serialization/deserialization whose timing does not
depend on secret contents, under an explicit policy for lengths and shape.
Constant time does not mean identical elapsed time for differently sized
messages; what may vary must be declared public. The general requirement is
secret-independent control flow and memory access, including outside the
cryptographic primitive. See [BearSSL's constant-time guidance](https://www.bearssl.org/constanttime.html).

A library-owned binary codec gives us control over that implementation, but
does not establish the property by itself. Strings, collection lengths,
enum variants, validation errors, allocations, and user-defined Serde code
can all introduce value-dependent work. Supporting arbitrary `Serialize` /
`Deserialize` implementations cannot guarantee constant-time behavior for
the whole operation.

Before claiming such a guarantee, define supported types, permitted public
shape/length information, and restrictions on custom implementations. A
stricter profile may need bounded shapes, fixed-width encodings, padding,
and controlled encoders/decoders, with implementation-level verification.
Padding ciphertext to a fixed size alone does not make the preceding
serialization constant-time. Authentication must complete before decoding
the plaintext blob. This is a design requirement to investigate, not a
guarantee made by these example programs or a constant-time audit result.

**Investigation candidate: `serdect`.** It is already a dependency of
`stack-encrypt`. Review its supported encodings and precise constant-time
guarantees, including decoding/error behavior and length assumptions. Assess
where it can help with ciphertext/byte serialization and whether any of its
techniques apply to the `OpaqueBlob` codec. Do not assume guarantees for byte
encoding extend to serializing arbitrary objects through Serde. This is a
follow-up investigation, not a completed assessment or codec selection.

## 2. Encrypt selected fields into a chosen output layout

**Intent:** store an ordinary record with plaintext `id` and `created_at`,
and independently encrypted `name` and `email`. The output type states the
layout. The two encrypted fields need no search indexes.

The proposed ciphertext Serde implementation makes persistence compositional:
ordinary Serde derives on the output encode plaintext fields normally and
ciphertext fields as Base64 envelopes. There is no manual `Node` traversal.

```rust
use serde::{Deserialize, Serialize};
use stack_encrypt::{
    Ciphertext, DecryptFrom, DecryptInto, EncryptFrom, EncryptInto, StackCipher,
};
use std::error::Error;

#[derive(Debug, PartialEq)]
struct User {
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let writer = StackCipher::new().await?;
    let keyset = writer.default_keyset();
    let user = User {
        id: 42,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
        created_at: 1_700_000_000,
    };

    // The output type selects the conversion and declares its own contexts.
    let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;
    assert_eq!(encrypted.id, user.id);
    assert_eq!(encrypted.created_at, user.created_at);

    // Persist the typed output, including both plaintext and ciphertext fields.
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("user.json");
    std::fs::write(&path, serde_json::to_vec(&encrypted)?)?;

    // Later: deserialize the same output layout and recover the plaintext type.
    let reader = StackCipher::new().await?;
    let loaded: EncryptedUser = serde_json::from_slice(&std::fs::read(&path)?)?;
    let restored: User = User::decrypt_from(loaded, &reader).await?;
    assert_eq!(restored, user);
    Ok(())
}
```

**Context and execution:** `name` uses the structured context
`("users", "name")`, and `email` uses `("users", "email")`. The keyset is
shared, but each encrypted field receives its own data key. One conversion
batches those key requests. The decrypt derive reconstructs `User`, opening
the ciphertext fields and copying the passthrough fields back.

**Plaintext semantics:** copying `id` does not automatically bind the sealed
fields to it. Both plaintext fields remain unencrypted and unauthenticated.
That is the requested passthrough behavior, not a promise of whole-record
integrity. The example's name/email contexts distinguish columns, not rows.

If the application wants row binding, it can use the existing
`user.encrypt_into_with_context(&keyset, expected_id)` entry point and the
matching `User::decrypt_from_with_context(loaded, &reader, expected_id)`.
The effective contexts then become `(("users", "name"), expected_id)` and
`(("users", "email"), expected_id)`. The reader supplies the expected id
from its record lookup. That is an explicit variation, not an automatic
effect of the passthrough attribute.

**Existing `context_field` support:** the derive does have
`#[stash(context_field)]`, but its current behavior is to store the
caller-supplied context in an output field and use it again when decrypting.
It does not read an id from the plaintext `User`. It also supplies the complete
context: the macro rejects combining it with a literal `context = "users"`.
Because the current `struct = User` form requires that literal, the attribute
cannot currently be used on example 2's field-by-field declaration.

**Separate source from storage:** obtaining context from plaintext fields
and carrying context into the encrypted output are independent choices.
An extended derive could read `User.id`, combine it with the declared field
contexts, and also copy it into `EncryptedUser.id`. That would enable row
binding without passing the id twice. The same model should accommodate
several source fields, such as `(tenant_id, id)`, with explicit ordering and
grouping.

Alternatively, context can be passed as an argument and stored, passed and
not stored, or derived from plaintext fields without being stored. In either
non-stored case, the reader needs equivalent context from elsewhere before
decrypting. Source selection and storage should be separately expressible;
whether one annotation can conveniently request both remains a syntax choice.
Today's `context_field` only covers the caller-supplied-and-stored case.

For the source-derived-and-stored case, a reader could use the stored id,
with an optional independently supplied expected id to reject a whole record
moved to another destination. Changing the stored id alone must fail
decryption. The values needed to reconstruct context must be available
without first opening the ciphertext that requires them.

**Review point:** the declaration is concise, but requires an explicit
`EncryptedUser` type. A future source-side derive could generate that type;
it should generate this same layout and context behavior. Also decide whether
`User::decrypt_from(...)` is the desired public decrypt spelling before
adding a competing no-context `loaded.decrypt_into(...)` convenience.

## 3. Use the same layout model with a searchable email target

**Intent:** keep the same plaintext fields, encrypt the name normally, and
store the email's ciphertext plus an equality term. Search terms come from
the original typed plaintext through their declared operation, not from the
JSON encoding used to persist the output.

`SearchableEmail` is an application-defined scalar target. It uses the caller
context supplied by the outer record: `("users", "email")`. It does not
declare another fixed context or append another `email` component. The
`ciphertext` and `equality` member names are output layout, not additional
cryptographic context segments.

```rust
use serde::{Deserialize, Serialize};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{
    nonempty, Ciphertext, DecryptFrom, DecryptInto, EncryptFrom, EncryptInto,
    StackCipher,
};
use std::error::Error;

#[derive(Debug, PartialEq)]
struct User {
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(plaintext = String)]
struct SearchableEmail {
    ciphertext: Ciphertext,
    equality: EqualityTerm,
}

#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[stash(struct = User, context = "users")]
struct SearchableUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: SearchableEmail,
    #[stash(passthrough)]
    created_at: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let writer = StackCipher::new().await?;
    let keyset = writer.default_keyset();
    let alice = User {
        id: 42,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
        created_at: 1_700_000_000,
    };
    let bob = User {
        id: 43,
        name: "Bob".to_owned(),
        email: "bob@example.com".to_owned(),
        created_at: 1_700_000_100,
    };

    // One collection conversion batches key generation across both users.
    let users = vec![alice, bob];
    let encrypted: Vec<SearchableUser> = users.encrypt_into(&keyset).await?;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("users.json");
    std::fs::write(&path, serde_json::to_vec(&encrypted)?)?;

    // Later: a query uses the same keyset, field context, and equality operation.
    let reader = StackCipher::new().await?;
    let query_keyset = reader.default_keyset();
    let wanted_email = "alice@example.com".to_owned();
    let query: EqualityTerm = wanted_email
        .encrypt_into_with_context(
            &query_keyset,
            nonempty!("users").with("email"),
        )
        .await?;

    // A file-backed comparison demonstrates matching without a SQL adapter.
    let loaded: Vec<SearchableUser> =
        serde_json::from_slice(&std::fs::read(&path)?)?;
    let matches: Vec<SearchableUser> = loaded
        .into_iter()
        .filter(|row| row.email.equality == query)
        .collect();
    assert_eq!(matches.len(), 1);

    // The query term cannot decrypt. Open the matched ciphertext rows in a batch.
    let restored: Vec<User> = Vec::<User>::decrypt_from(matches, &reader).await?;
    assert_eq!(restored.as_slice(), &users[..1]);
    Ok(())
}
```

The filter is an in-memory scan over persisted encrypted records, not a
claim of database index use. It demonstrates the entire query contract:
derive the term, compare it with the stored term, and open the matched
ciphertext. An equality match is not authentication of the stored record;
the decrypt operation authenticates its encrypted fields. Passthrough
semantics are the same as in example 2.

Collection conversion is already supported by Stack's blanket
`EncryptFrom<Vec<S>> for Vec<T>` implementation when `T: EncryptFrom<S>`
and its context supports cloning. It collects every row's pending operations
before dispatch: these two users require four data keys (name and email for
each), issued through one batched `generate_keys` call. Equality terms use
the current local index-key backend. This count concerns encryption work,
not client initialization or authentication.

One logical `generate_keys` call is not an unlimited single HTTP request:
the KMS client chunks batches according to its configured key-count limit.
This four-key example fits in one normal request; larger collections may
span several requests without changing the public call.

The matching collection decrypt implementation batches retrieval across
rows, with one `retrieve_keys` call per keyset represented in the ciphertext.
An empty collection requires no data-key call. Collection order is preserved
by the conversion; no new whole-collection authentication is implied.

This target-directed vector is a vector of independent output records. It
is distinct from encrypting a plaintext vector into a single
`StackCipherText` sequence tree, and from wrapping the vector in `OpaqueBlob`
to encode/encrypt the whole collection as one value. Batching is a property
of execution, not a change to the chosen layout.

This example uses the common field context for all rows so one query term
can search them. Adding a row id to that context would also scope the term
to that row. Separating ciphertext row binding from column-wide search
context is a further design question, not something these examples silently
promise. Likewise, applications querying across keysets need the appropriate
term per keyset; no cross-keyset comparison is implied.

### EQL targets: a concrete adapter boundary

The example above is a generic searchable layout, **not an EQL payload**.
For EQL, use the adapter's types, metadata, serialization, and query target.
For example, today's `eql_bindings::v4::text::TextEq` already represents an
email ciphertext plus equality term; `TextEqQuery` represents the query.

The following separate field-level program uses existing APIs and avoids
the proposed `Ciphertext` and passthrough attributes. It needs `eql-bindings`
with its `stack-encrypt` feature, `stack-encrypt`, `serde_json`, `tempfile`,
and `tokio`. It is marked `no_run` because it needs live credentials; it has
been checked against source signatures here, not compiled or executed.

```rust
use eql_bindings::{
    v4::text::{TextEq, TextEqQuery},
    Identifier,
};
use stack_encrypt::{DecryptFrom, EncryptInto, StackCipher};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let writer = StackCipher::new().await?;
    let keyset = writer.default_keyset();
    let column = Identifier::for_column("users", "email")?;
    let email = "alice@example.com".to_owned();

    let encrypted: TextEq = email
        .encrypt_into_with_context(&keyset, column.clone())
        .await?;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("email.eql.json");
    std::fs::write(&path, serde_json::to_vec(&encrypted)?)?;

    let reader = StackCipher::new().await?;
    let query_keyset = reader.default_keyset();
    let query: TextEqQuery = email
        .encrypt_into_with_context(&query_keyset, column.clone())
        .await?;
    let loaded: TextEq = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(loaded.hm, query.hm);

    // Supply the expected column, so stored identifier metadata is checked too.
    let restored: String = loaded.decrypt_into(&reader, column).await?;
    assert_eq!(restored, email);
    Ok(())
}
```

`TextEq` includes its EQL version, identifier, ciphertext, and equality term.
Its context is `NonEmpty<Identifier>`. The typed identifier comes from the
application's expected table/column on both writes and reads; decryption
checks it against the stored identifier before opening the ciphertext.
The `v4` namespace is intentional: this Rust producer profile targets EQL
v4, not the TypeScript EQL v3 integrations.

There is a gap before we can simply replace `SearchableEmail` with `TextEq`
in the outer derive. That derive currently passes `CallerContext`; EQL's
target needs `NonEmpty<Identifier>` and carries its identifier in the output.
The context adaptation must be designed explicitly, including whether caller
extensions are representable. The EQL example demonstrates what that adapter
must preserve without inventing an implicit conversion or a nonexistent SQL
client API. PostgreSQL DDL, parameter binding, and index engagement are a
separate adapter example to add once that boundary is settled.

## What to review across the three workflows

| Question | Concrete choice made by these examples |
| --- | --- |
| What is one encrypted unit? | One `OpaqueBlob` encoding in example 1; one selected field in examples 2 and 3 |
| How is the layout selected? | Ordinary encrypt returns an opaque value; `EncryptInto` selects a declared output |
| How is persistence exposed? | Canonical bytes for one ciphertext; Serde composed over a typed layout |
| How is plaintext recovered? | Decrypt/decode into `OpaqueBlob<User>` and unwrap, or use the target's `DecryptInto` declaration |
| How do indexes fit? | Additional field targets under the same layout/execution model |
| Who chooses context? | The application for a blob; the layout plus optional caller extensions for fields; an explicit identifier for EQL |
| Do examples need plans or visitors? | No; those remain implementation and advanced composition mechanisms |
| Is an encrypted output type generated automatically? | No; the layout examples deliberately define it |

The principal unresolved choices exposed by the examples are the opaque
ciphertext name and storage contract, the public decrypt spelling, the blob
codec and timing contract, EQL context adaptation, and optional source-side output
generation. None requires reintroducing public `encrypt_as`.

## Source checks and validation limits

The draft was checked against the existing
[target traits and convenience methods](../../packages/stack-encrypt/src/target/operations.rs),
[context composition](../../packages/stack-encrypt/src/target/context.rs),
[derive implementation](../../packages/stack-encrypt-derive/src/encrypt.rs),
[decrypt derive](../../packages/stack-encrypt-derive/src/decrypt.rs),
[canonical leaf encoding](../../packages/stack-encrypt/src/cipher.rs), and
[EQL targets](../../packages/eql/crates/eql-bindings/src/v4/text.rs).

All four programs were parsed successfully by `rustfmt` using Rust edition
2024. All local links resolve; code fences and whitespace were checked.
These checks establish syntax and document integrity, not type correctness.

The candidate APIs are not implemented by this document. The three proposed
programs cannot yet be typechecked against the repository. No live encryption,
database execution, or cryptographic compatibility tests are claimed. Once the surface is agreed
and implemented, promote these programs to executable examples and verify
storage round trips, matching queries, and context mismatches.
