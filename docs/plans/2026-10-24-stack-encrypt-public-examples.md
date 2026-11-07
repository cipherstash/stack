# Stack Encrypt: complete public API examples for review

Date: 24 October 2026. Implementation status checked on 7 November 2026,
against `next` at commit `e4990e49b`.

This document tests the proposed public Rust API of Stack Encrypt against
three complete workflows. The code in it is a proposal. The code does not
compile against today's crate. This document is not documentation for a
released version.
Reviewers need to decide whether the API these examples show is the one to
build.

The questions to settle are listed in
"What to review across the three workflows", near the end.

The three workflows are:

1. Encrypt a whole user record as one encrypted value, store it, load it,
   and decrypt it.
2. Encrypt only some fields of the record, store it, load it, and decrypt
   it.
3. Do the same as workflow 2, but also store a search term for the email.
   Then build a query and use it to find the record.

A fourth program shows how the same search works today with the Encrypt
Query Language (EQL) types, using APIs that already exist.

## Related documents

This document is a companion to the
[API review log](2026-10-24-stack-encrypt-api-review.md). Two other
documents cover related ground:

- The separate [context examples](2026-10-24-stack-encrypt-context-examples.md)
  work through nine scenarios. They cover where a context comes from, whether
  the context is stored, and what a decrypt call takes as input. The
  attributes in that document are proposals, not implemented APIs.
- The [JSON operation contract](2026-10-25-stack-encrypt-json-operations.md)
  covers all the JSON workflows planned for the first release, with Rust,
  dynamic, and SQL examples, including extraction and walks.

The user clarified on 25 October 2026 that this API is an early prototype.
The new API does not need to stay backward compatible with the old APIs.

On 7 November 2026, the user decided that the stored format must not break
from now on, because the Go customer builds on Go `v0.1.0-rc.3`. The stored
format is what is written to the database, such as ciphertext envelopes and
search terms. The APIs can still change. This replaces the decision of 25
October 2026 for stored data. See the [API
plan](2026-10-24-stack-encrypt-api-plan.md#stored-format-must-stay-compatible-from-7-november-2026).

## Terms used in this document

The Stack Encrypt crate is `packages/stack-encrypt`. This document uses
these terms from it:

- **Keyset**: a set of keys in ZeroKMS, the CipherStash key service.
  Every encrypted value is sealed under one keyset, and the sealed value
  records which keyset that was.
- **Data key**: the key that encrypts one value. Stack Encrypt requests data
  keys from ZeroKMS in batches.
- **Context**: data that a ciphertext is tied to, such as
  `("users", "email")` or a record id. Decryption needs the same context.
  Search terms are also derived from it. See [Context and
  AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad).
- **AAD**: additional authenticated data. Encryption checks it for one ciphertext, but does not encrypt it. Stack Encrypt builds it from the
  context.
- **Leaf**: one encrypted value. "Sealing" a leaf means encrypting and
  authenticating it.
- **Envelope**: the complete stored form of a ciphertext. It includes the
  sealed bytes and the metadata needed to fetch the key again, so the caller
  does not store anything separately.
- **Target**: a Rust type that a value is encrypted into or decrypted from.
  The target decides which ciphertext and which search terms are produced.
- **Passthrough field**: a field copied unencrypted from the plaintext type
  to the encrypted type, and back again on decrypt.
- **Plan**: the internal description of which fields a conversion encrypts,
  indexes, or passes through. Today a caller can build one with
  `Plan::fields()`.
- **Equality term**: a value stored next to a ciphertext that lets a query
  find an exact match without decrypting.
- **Zeroize**: overwrite memory that held plaintext, so the plaintext does
  not stay in memory after use. `Zeroize` is the Rust trait that does this.

## Decisions already made, and what these examples propose

The first parts of this section record decisions made on 25 October 2026.
The table after them lists every API surface in the examples and its status.

### Ownership decision (25 October 2026)

`encrypt` and `encrypt_into` take ownership of (consume) their inputs. This
includes the variants that take a context. Their implementations must guard
the owned plaintext and temporary buffers, so they are cleaned up on
success, on error, and when the request is dropped. Passthrough fields are
deliberately moved into the output.

Other parts of this decision:

- The capabilities for a single ciphertext are named `OpaqueEncode` and
  `OpaqueDecode`.
- Plaintext types must implement `Zeroize`. No new cleanup trait is planned.
- `Serialize` alone does not establish the cleanup contract for
  `OpaqueBlob<T>`.

The candidate programs below were written before the `Zeroize` requirement.
When making them executable, update their source derives, and remove any
reuse of input that has been consumed.

### Decrypt decision (25 October 2026)

Stack Encrypt keeps two ways to decrypt:

- the direct `keyset.decrypt` and `decrypt_with_context`, for an opaque
  ciphertext;
- the destination-directed `T::decrypt_from` and
  `decrypt_from_with_context`, for a declared target.

A successful call returns an ordinary owned `T: Zeroize`. The caller is then
responsible for cleaning it up. Stack Encrypt guards intermediate plaintext.

The API must support results that are wiped when they are dropped, if the
caller asks for them, without forcing a wrapper on every caller. `Zeroize`
alone does not wipe a returned value when it is dropped. These are accepted
API contracts. This document does not claim that the prototype already
implements them.

### Collection decision (25 October 2026)

The direct `keyset.encrypt(value)` takes one single-value input and produces
one `Ciphertext`. It does not encrypt a collection element by element.

To encrypt each element of a collection in one batch, use `EncryptInto`,
for example:
`let encrypted: Vec<Ciphertext> = vec![1_i32, 3_i32].encrypt_into(&keyset).await?`.

`keyset.encrypt(OpaqueBlob::new(vec![1_i32, 3_i32])).await?` produces one
ciphertext for the encoded collection instead.

The latest recommendation applies the same rule to byte vectors. No wrapper
or special case is needed to keep the prototype's behaviour. Pull request
#1501 differs: it encrypts `Vec<u8>` and `[u8; N]` as one value. The [API
plan](2026-10-24-stack-encrypt-api-plan.md#differences-between-merged-code-and-this-plan)
records this as a question for the user. These calls
need the proposed opaque ciphertext and support for targets that take no
context.

### Status of each API surface

| Surface | Status in this review | Implementation on 7 November 2026 |
| --- | --- | --- |
| `keyset.encrypt(value)` and `encrypt_with_context(value, context)` | Agreed direction | Done for one value (#1404) |
| `value.encrypt_into(&keyset)` and `encrypt_into_with_context` | Retained existing entry points | Done for one value and for `Vec<S>` (#1404, #1501) |
| No public `encrypt_as` in these examples | Agreed direction | Still open. `encrypt_as` is still public |
| `#[stash(passthrough)]` on output fields | Accepted in principle | Still open. In progress in #1504 |
| A fixed context on a scalar output derive | Agreed direction; not required by these examples | Still open |
| `OpaqueBlob<T>` | Agreed wrapper direction; provisional name | Still open. In progress in #1503 |
| `Ciphertext` | Proposed name for an opaque single-value ciphertext | Done (#1404) |
| `Ciphertext::to_bytes` / `from_bytes` | Proposed direct access to the canonical sealed-leaf encoding | Done (#1404). The envelope is unchanged |
| `Ciphertext: Serialize + Deserialize` | Proposed: Base64 for human-readable formats, bytes for binary formats | Done (#1404) |
| Encoded ciphertext field targets | Accepted; final names remain for the naming pass | Still open |
| `Ciphertext` as an encryption or decryption target | Proposed single-value target | Done (#1404). `Vec<u8>` is one value, unlike the recommendation (#1501) |
| Decrypt into `OpaqueBlob<T>`, then `into_inner()` | Proposed symmetric decoding path | Still open. In progress in #1503 |
| Direct `decrypt` / `decrypt_with_context` | Accepted ordinary decrypt pair | Done for one value (#1404) |
| `User::decrypt_from` / `decrypt_from_with_context` | Accepted destination-directed pair | Done for one value and `Vec` (#1404, #1501). Records are in #1504 |
| `SearchableEmail` in example 3 | Application-defined target | Still open. #1504 turns example 3 into a test |

The first three Rust programs use the proposed `OpaqueBlob`, `Ciphertext`,
and passthrough APIs, or some of them. Each is a complete candidate program.
None is claimed to compile against today's crate. The names and contracts in
the table can still change where they are marked proposed or provisional.

### Notes on the proposed types

The proposed opaque ciphertext deliberately carries no plaintext type. The
type that the decrypt call expects selects how the plaintext is decoded. A
typed wrapper is still an open alternative.

The ciphertext's byte decoder
only parses a stored envelope. Authentication happens when it is decrypted.
The new Rust implementation and the dynamic implementation must agree on
the context and leaf encodings. On 24 October 2026 they did not need to keep the prototype's encoding. Since 7 November 2026, they must keep reading the encodings that Go rc.3 writes.

The trait name `DecryptFrom` may surprise readers. The trait supplies the
convenience functions, while `#[derive(DecryptInto)]` describes how an
encrypted output recovers its plaintext. These examples keep that existing
split visible, rather than redesigning it without saying so.

### What the examples leave out, and why

The examples deliberately keep plans and operation descriptions out of the
application code. The application code shows only the public calls.

Each main example is a separate program, with all imports and types shown.
All of them use the same user fields and made-up data. `created_at` is an
`i64` Unix timestamp in seconds, so that configuring a date library does not
distract from the encryption API.

Files stand in for a database. The programs do encode, write, read, and
decode their stored forms. The files are written to a temporary directory.
The directory is removed when the program exits.

## Setup shared by the programs

The proposed programs use these crates:

- `stack-encrypt`, with its default `http` feature;
- `serde`, with `derive`;
- `serde_json`;
- `tempfile`;
- `tokio`, with `macros` and `rt-multi-thread`.

No published version of `stack-encrypt` supplies all the proposed APIs yet.
This draft therefore gives no Cargo manifest, because one would suggest the
programs can be installed and run.

`StackCipher::new()` uses the configured ZeroKMS credentials. Those come
from a CLI login, or from these environment variables: `CS_CLIENT_ID`,
`CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`, and `CS_WORKSPACE_CRN`.

The second client in each program stands for a later reader that uses the
same authorised configuration. The examples select the default keyset to
keep them short. A tenant keyset that the application has already selected
can be used in its place.

Decryption uses the client, because the sealed value records its keyset id.
The reader still needs access to the matching keys and the correct context.
The examples do not rely on in-memory fake keys surviving a reload.

## 1. Encrypt the whole user through an explicit blob wrapper

**What this example shows:** how to store one encrypted document. All four
fields, including the id and creation time, are inside one encrypted
serialization. The stored ciphertext contains no fields that can be read
separately, and no search terms.

`OpaqueBlob::new(user)` explicitly asks for that treatment. Stack Encrypt
owns the serialization and the matching deserialization, so each
application does not have to choose and call a codec. The proposed wrapper
takes ownership of the input. `new` only wraps the value. The
encryption call returns any serialization error.

The context names the application's document schema
(`"user-document-v1"`). The context also binds this document to a record id
that the application knows from outside the ciphertext.

In this draft, the wrapper accepts `Serialize + Zeroize` on write and
`DeserializeOwned + Zeroize` on read. This does not claim that every Serde
implementation can meet a constant-time contract.

The first version of the
wrapper has one versioned binary codec that the library chooses. The caller
cannot choose a codec. Choosing and specifying that codec is still design
and implementation work. This document does not claim that any binary format
is implemented, or that any is constant-time.

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

### What the API must guarantee for example 1

- The serialized bytes are one encrypted leaf under one data key.
- The envelope contains the metadata needed to fetch the key again. The
  caller never needs to save an initialisation vector (IV) or a key tag
  separately.
- A different context must fail to open the ciphertext.
- Stack Encrypt owns the matching encode and decode pair, and the contract
  for keeping them compatible.
- The blob format's identifier and version must be authenticated, for
  example by putting them inside the encrypted payload. Decoding then does
  not depend on guessing a codec, or on format metadata that is not
  authenticated.
- The blob can reuse the canonical outer ciphertext envelope. The blob
  payload is a new, explicit format. It must not quietly reinterpret raw
  bytes that were encrypted before.
- Changes to the application's schema still need explicit handling. A codec
  version does not migrate changes to `User` automatically.

### Encrypting without an application context

Without an application context, use the form
`keyset.encrypt(OpaqueBlob::new(user))`. A matching no-context
`reader.decrypt(loaded)` is accepted, so that encrypt and decrypt match.
Since #1404, `keyset.decrypt(ciphertext)` takes one argument for an opaque
value. `OpaqueBlob` itself is not merged.
This document uses an explicit context in the full example so that the
saved format is unambiguous.

### What the wrapper means

`OpaqueBlob<User>` is the request on the plaintext side, and the decoded
value. It is not the stored ciphertext type. `Ciphertext` is still the
stored envelope. `into_inner()` returns an ordinary `User`.

The wrapper does not by itself promise to zeroize arbitrary input or
returned types. The codec should keep temporary plaintext buffers in memory
that can be wiped.

`#[derive(Encrypt)]` on `User` currently means a structural tree of
ciphertexts, one for each field. That derive cannot replace wrapping the
value as one blob.

### Timing contract to investigate

The goal is serialization whose timing does not depend on the secret
contents, in both directions. An explicit policy sets what may vary in
lengths and shape.

Constant time does not mean that messages of different sizes take the same
elapsed time. The policy must declare which properties may vary, and treat
them as public. In general, neither control flow nor memory access may
depend on secrets. That applies outside the cryptographic primitive too.
See [BearSSL's constant-time guidance](https://www.bearssl.org/constanttime.html).

A binary codec that the library owns gives us control over the
implementation, but does not give the property by itself. Each of these can
add work that depends on the values:

- strings;
- collection lengths;
- enum variants;
- validation errors;
- memory allocations;
- Serde code that users write.

Supporting arbitrary `Serialize` and `Deserialize` implementations cannot
guarantee constant-time behaviour for the whole operation.

Before claiming such a guarantee, define these things:

- the supported types;
- which shape and length information may be public;
- the restrictions on custom implementations.

A stricter set of supported types may need bounded shapes, fixed-width encodings, padding,
and controlled encoders and decoders, with verification at the
implementation level. Padding the ciphertext to a fixed size does not by
itself make the serialization before it constant-time. Authentication must
finish before the plaintext blob is decoded.

This section states a design requirement to investigate. These example
programs make no such guarantee. This section is not the result of a
constant-time audit.

**Candidate to investigate: `serdect`.** `serdect` is already a dependency
of `stack-encrypt`. The investigation needs to:

- review its supported encodings and its exact constant-time guarantees,
  including its timing when decoding and on errors, and its assumptions
  about lengths;
- assess where it can help serialize ciphertexts and bytes;
- assess whether any of its techniques apply to the `OpaqueBlob` codec.

Do not assume that its guarantees for encoding bytes extend to serializing
arbitrary objects through Serde. This is a follow-up investigation. It is
not a finished assessment. It does not select a codec.

## 2. Encrypt selected fields into a chosen output layout

**What this example shows:** how to store a record in which `id` and
`created_at` stay as plaintext. `name` and `email` are each encrypted
separately. The output type declares the layout. The two
encrypted fields need no search indexes.

The proposed Serde implementation for `Ciphertext` lets persistence be
built from ordinary parts. Ordinary Serde derives on the output type encode
the plaintext fields as usual, and encode the ciphertext fields as Base64
envelopes. The application does not walk any `Node` values by hand.

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

### Context and execution in example 2

`name` uses the structured context `("users", "name")`, and `email` uses
`("users", "email")`. The two fields share the keyset, but each encrypted
field gets its own data key. One conversion sends the key requests for both
fields in one batch. The decrypt derive rebuilds `User`: it opens the
ciphertext fields and copies the passthrough fields back.

### What passthrough fields do and do not protect

Copying `id` does not bind the sealed fields to it. Both plaintext fields
stay unencrypted and unauthenticated. That is the passthrough behaviour that
was asked for. It does not promise integrity for the whole record. The
example's `name` and `email` contexts tell columns apart, not rows.

If the application wants each ciphertext bound to its row, it can use the
existing entry point `user.encrypt_into_with_context(&keyset, expected_id)`
and the matching
`User::decrypt_from_with_context(loaded, &reader, expected_id)`. The
contexts that take effect are then `(("users", "name"), expected_id)` and
`(("users", "email"), expected_id)`. The reader supplies the expected id
from its record lookup. This is an explicit variation. The passthrough
attribute does not cause it.

### Existing `context_field` support

The derive already has `#[stash(context_field)]`. Its current behaviour is
to store the context the caller supplied in an output field, and to use it
again when decrypting. It does not read an id from the plaintext `User`.

`context_field` also supplies the complete context, so the macro refuses to
combine it with a literal `context = "users"`. The current `struct = User`
form requires that literal. As a result, the attribute cannot be used today
in example 2's field-by-field declaration.

### Where context comes from, compared with where it is stored

Taking context from plaintext fields and carrying context into the encrypted
output are separate choices. An extended derive could read `User.id`,
combine it with the field contexts declared on the type, and also copy it
into `EncryptedUser.id`. That would bind each ciphertext to its row without
passing the id twice. The same model should handle several source fields,
such as `(tenant_id, id)`, with explicit ordering and grouping.

There are other combinations. Context can be:

- passed as an argument and stored;
- passed as an argument and not stored;
- taken from plaintext fields and not stored.

In either case where the context is not stored, the reader needs the same
context from somewhere else before decrypting. The API should let callers
express the source and the storage separately. Whether one annotation can
ask for both is still a syntax choice. Today's `context_field` only covers
the case where the caller supplies the context and it is stored.

Suppose the context is taken from plaintext fields and also stored. A
reader could then use the stored id. To reject a whole record that was moved
to another place, the reader could also supply an expected id from
elsewhere. Changing the stored id alone must make decryption fail. The values needed to rebuild the
context must be available without first opening the ciphertext that
requires them.

### Review points for example 2

The declaration is short, but it requires an explicit `EncryptedUser` type.
A future derive on the source type could generate that type. If it does, it
should generate this same layout and the same context behaviour.

Reviewers also need to decide whether `User::decrypt_from(...)` is the
public spelling for decryption that we want. That decision comes before
adding a competing no-context convenience, `loaded.decrypt_into(...)`.

## 3. Use the same layout model with a searchable email target

**What this example shows:** the same plaintext fields as example 2, with
the name encrypted as before. The email is stored as its ciphertext plus an
equality term. Search terms are made from the original typed plaintext,
through the operation the target declares. They are not made from the JSON
encoding used to store the output.

`SearchableEmail` is a scalar target that the application defines. It uses
the context that the outer record supplies: `("users", "email")`. It does
not declare a fixed context of its own. It does not add another `email` part
to the context.

The member names `ciphertext` and `equality` only describe the output
layout. They do not add parts to the cryptographic
context.

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

### What the query in example 3 shows

The filter scans the stored encrypted records in memory. It does not claim
that a database index is used. The filter shows the whole query contract:

1. Make the query term.
2. Compare it with the stored term.
3. Open the matching ciphertext.

An equality match does not authenticate the stored record. The decrypt
operation authenticates the record's encrypted fields. Passthrough fields
work as they do in example 2.

### How collection conversion batches key requests

Stack Encrypt already supports collection conversion, through its blanket
implementation `EncryptFrom<Vec<S>> for Vec<T>` when `T: EncryptFrom<S>` and
the target's context can be cloned. Since #1501, the owned API has the same
batching for `Vec<S>` into `Vec<T>`. The batching counts below apply to
both.

The conversion collects every row's
pending operations before sending any of them. The two users need four data
keys, one each for name and email in each row. All four are issued through
one batched `generate_keys` call. Equality terms use the current local
backend for index keys.

This count is about the encryption work only. It
does not include setting up or authenticating the client.

One logical `generate_keys` call is not always a single HTTP request. The
KMS (key management service) client splits a batch into chunks, according
to its configured limit on the number of keys. This example's four keys fit
in one normal request. A larger collection may need several requests, with
no change to the public call.

The matching collection decrypt implementation also batches key retrieval
across rows. It makes one `retrieve_keys` call for each keyset found in the
ciphertexts. An empty collection needs no data-key call. The conversion
keeps the collection's order. It does not add any authentication of the
collection as a whole.

### Three different ways to encrypt a vector

This target-directed vector is a vector of separate output records. It is
different from both of these:

- encrypting a plaintext vector into a single `StackCipherText` sequence
  tree;
- wrapping the vector in `OpaqueBlob`, to encode and encrypt the whole
  collection as one value.

Batching is a property of how the work is run. It does not change the
layout that was chosen.

### Limits of the search context

This example uses the same field context for every row, so that one query
term can search all of them. Adding a row id to that context would also
limit the term to that row. How to bind each ciphertext to its row while
keeping a search context that covers the whole column is still an open
design question. These examples do not promise it.

In the same way, an application that queries across keysets needs a
separate query term for each keyset. The examples do not imply any
comparison across keysets.

### EQL targets: a concrete adapter boundary

The example above is a generic searchable layout. It is **not an EQL
payload**. For EQL, use the adapter's types, metadata, serialization, and
query target. Here, the adapter is the `eql-bindings` crate. The crate
converts between Stack Encrypt values and the stored EQL format.

For example, today's `eql_bindings::v4::text::TextEq` already contains an email
ciphertext plus an equality term. `TextEqQuery` is the matching query type.

The program below is a separate example for one field. It uses existing APIs
and avoids the proposed `Ciphertext` and passthrough attributes. It needs:

- `eql-bindings`, with its `stack-encrypt` feature;
- `stack-encrypt`;
- `serde_json`;
- `tempfile`;
- `tokio`.

The program is marked `no_run` because it needs live credentials. The program
has been checked against the source signatures. It has not been compiled or
run.

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

Note added on 7 November 2026: this program no longer uses existing APIs
as written. Since #1404, the crate-root `EncryptInto` and `DecryptFrom` are
the owned traits. `TextEq` implements only the structural declarations. So
the program needs `stack_encrypt::target::legacy::{DecryptFrom,
EncryptInto}`, or `keyset.encrypt_as`, as `eql-bindings` uses. This was
checked by reading the source, not by compiling.

`TextEq` includes its EQL version, its identifier, the ciphertext, and the
equality term. Its context type is `NonEmpty<Identifier>`. The application
supplies the typed identifier for the expected table and column, on both
writes and reads. Decryption checks it against the stored identifier before
opening the ciphertext.

The `v4` namespace is deliberate: this Rust producer targets EQL v4.
The TypeScript integrations use EQL v3.

### Gap before `TextEq` can replace `SearchableEmail`

There is a gap before `TextEq` can replace `SearchableEmail` in the
outer derive. That derive currently passes a `CallerContext`. The EQL target
needs a `NonEmpty<Identifier>`, and stores its identifier in the output.

The conversion between the two contexts must be designed explicitly. The
design includes whether extensions that the caller adds to the context can
be represented. The EQL example shows what that adapter must keep. It does
not invent an implicit conversion, or an SQL client API that does not exist.

PostgreSQL DDL (the statements that create tables and indexes), parameter
binding, and whether queries use the index belong in a separate adapter
example. That example is to be added once the boundary is settled.

## What to review across the three workflows

Each row of this table is one design question. The second column gives the
answer these examples chose.

| Question | Concrete choice made by these examples |
| --- | --- |
| What is one encrypted unit? | One `OpaqueBlob` encoding in example 1; one selected field in examples 2 and 3 |
| How is the layout selected? | Ordinary encrypt returns an opaque value; `EncryptInto` selects a declared output |
| How is persistence exposed? | Canonical bytes for one ciphertext; Serde composed over a typed layout |
| How is plaintext recovered? | Decrypt and decode into `OpaqueBlob<User>` and unwrap, or use the target's `DecryptInto` declaration |
| How do indexes fit? | Additional field targets under the same layout and execution model |
| Who chooses context? | The application for a blob; the layout plus optional caller extensions for fields; an explicit identifier for EQL |
| Do examples need plans or visitors? | No; those remain implementation and advanced composition mechanisms |
| Is an encrypted output type generated automatically? | No; the layout examples deliberately define it |

### Main open questions

The examples leave these questions open:

- What is the opaque ciphertext called, and what is its storage contract?
- What is the blob codec, and what is its timing contract?
- How is an EQL context adapted?
- Does a derive on the source type generate the output type?

None of them requires bringing back a public `encrypt_as`.

## Source checks and validation limits

The draft was checked against the existing code:

- [target traits and convenience methods](../../packages/stack-encrypt/src/target/operations.rs);
- [context composition](../../packages/stack-encrypt/src/target/context.rs);
- [derive implementation](../../packages/stack-encrypt-derive/src/encrypt.rs);
- [decrypt derive](../../packages/stack-encrypt-derive/src/decrypt.rs);
- [canonical leaf encoding](../../packages/stack-encrypt/src/cipher.rs);
- [EQL targets](../../packages/eql/crates/eql-bindings/src/v4/text.rs).

`rustfmt` parsed all four programs without errors, using Rust edition 2024.
All local links resolve. The code fences and whitespace were checked. These
checks confirm the syntax and the document's integrity, not that the types
are correct.

This document does not implement the candidate APIs. The three proposed
programs cannot yet be type-checked against the repository. No live
encryption, database runs, or cryptographic compatibility tests are claimed.
Once the API surface is agreed and implemented, turn these programs into
executable examples. Then verify the storage round trips, the matching
queries, and that a wrong context fails.
