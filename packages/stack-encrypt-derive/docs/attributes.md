# Attributes

All attributes live under `#[stash(...)]`. The four derives read the same
attributes: `EncryptFrom` / `DecryptInto` emit the structural declarations,
run over a borrowed plaintext; `EncryptTarget` / `DecryptSource` emit the
owned declarations (and the structural ones beside them as a bridge), run
over a plaintext handed over by value, and alone accept `passthrough`. Derive
one pair or the other on a record, not both.

## On the struct

| Attribute | Effect |
|---|---|
| `plaintext = Type` | The record is an encrypted form of `Type`, every field derived from the whole value. Repeatable: one impl per listed type. Omit it for an impl generic over the plaintext (see below). |
| `struct = Type` | The record encrypts the struct `Type` field by field: every derived field is derived from the plaintext field of its own name, under the pair `("<context>", "<field>")` (see [Structs, field by field](#structs-field-by-field)). Exclusive with `plaintext`; requires `context`. |
| `context = "..."` | With `struct` only: the first half of every field's inferred context — the stored data's name. Required, never inferred from the type's name, and must not be empty. |
| `context_type = Type` | The record's associated `Context`, for a record whose fields take the caller's context: what the caller passes. Defaults to `CallerContext`; `AeadContext` for a record made only of ciphertexts, so an `IntoAad`-only context type is accepted (see [Which context a record takes](#which-context-a-record-takes)). Not with `context_field` or `struct`. |
| `crate = "path"` | Where to find `stack_encrypt` in the generated code (default `::stack_encrypt`), for use through a re-export. |

`plaintext` must be an owned type: the generated impl has no lifetime to give
a reference. Without `plaintext`, each derive emits one impl generic over the plaintext,
bounded by what the fields accept: `EncryptedAge` below is `EncryptFrom<P>`
for any `P` that both `StackCipherText` and `EqualityTerm` accept, and
`DecryptInto<P>` for any `P` its `decrypt` field opens to. With
`plaintext`, the record accepts only the listed types (a field that holds
integers should not accept a `String`). Whether `Type` is a struct makes no
difference to `plaintext`: the derive sees a name, not a definition, and
derives every field from the whole value. Encrypting a struct field by
field is `struct = Type`, which the plaintext is rebuilt from with a struct
literal.

## On a field

| Attribute | Effect |
|---|---|
| `context_field` | Store the caller’s typed context here and recover it on decryption. Exactly one per record; excludes the other field attributes. |
| `identity = "..."` | With `struct` only: key this field under the segment `identity` instead of the plaintext field's name, so it is derived under `("<context>", "<identity>")`. One plain segment. The plan builder's `.identity(segment)`. |
| `from = field` / `from = 0` | With `struct` only: derive this field from `plaintext.field` (or `plaintext.0` for a tuple struct) when its name differs from its plaintext field's. A plaintext field has one output: two fields `from` one plaintext field are refused (a ciphertext with its terms is one `Encrypted<Terms>` field). |
| `default` / `default = expr` | Not derived: filled with `Default::default()` or `expr`. Never encrypted, never authenticated. |
| `decrypt` | Decryption opens this field (`DecryptInto` / `DecryptSource` only). Needed only when the field types cannot decide it — see below. |
| `passthrough` | With `struct` on the owned derives only: carry the plaintext field of this name (or `from = field`) into the record as it is, **not encrypted and not authenticated**, moved rather than cloned, and move it back on decryption. Keyed under nothing; excludes `identity`, `default` and `decrypt`. |

A field takes no `context = ".."` of its own, on any derive: it is a compile
error. A plan has exactly one context source, and every output sits under it.
All outputs of a `plaintext = T` record share the caller's context; every
field of a `struct` derive sits under the record's (`identity` keys it under
another segment of it). Writing one value under two different contexts, a
dual write, is a fields plan that picks the same source twice, not a derive.

Upgrading from 0.2.0, which accepted a field `context = ".."` and
`#[stash(nested)]`: removing the field literal (on a `plaintext = T` record),
writing `identity = ".."` in its place (on a `struct` derive field), or
removing `nested` each keys the field under a **different** context from the
one 0.2.0 used. Data written by 0.2.0 under the old form does not decrypt
under the new one, and its terms do not match new query terms, so re-encrypt
that data.

Each derive emits one declaration per plaintext, with an associated `Context`.
A record with `#[stash(context_field)]` on a field of type `T` requires
`NonEmpty<T>` for encryption and stores its inner value in that field. Decryption
takes `ExpectedContext<T>`. Its default checks only that the stored value is nonempty and then opens the record under whatever context it stores — so a ciphertext moved together with its stored context opens as if it belonged where it now sits. `NonEmpty<T>.into()` names the destination the caller believes it is opening; a stored context that differs is refused with `Error::ContextMismatch` before any key is retrieved. Either way the stored context is data the record arrived with, not something the cipher has authenticated.
`T` supplies the Vitamin C context encodings and implements `Clone`,
`MaybeEmpty`, and `PartialEq`. This metadata is not a separate encrypted field.

Otherwise, a `struct` derive, whose fields all carry their own contexts, uses
`DeclaredContext`. `().into()` or its default selects the
declared contexts unchanged; a nonempty caller context extends each base context.
A `plaintext` record, whose fields all take the caller's context, uses `CallerContext`, constructed
from a `NonEmpty<T>` or a supported integer. Both encodings and the descriptor's
structured identity are preserved when borrowing context data is converted into
an owned declaration. No context is inferred from a Rust type's name.

## Owned records

`#[derive(EncryptTarget, DecryptSource)]` takes the attributes above and
declares the record the owned way: `value.encrypt_into(&keyset)` consumes
the plaintext, and `Plaintext::decrypt_from(record, &cipher)` returns it.
The plaintext type is `Zeroize` (the trait bound says where the wiping
obligation lies), and the conversion wipes every plaintext field it seals.
What the caller may or must pass is the record's `ContextInput`:

| Record | Encrypt input | Decrypt input | A call |
|---|---|---|---|
| `struct = User, context = "users"` | `ContextExtension<DeclaredContext>` | the same | `user.encrypt_into(&keyset)`, or `.encrypt_into_with_context(&keyset, 7u64)` to extend every field's pair by the row id |
| `plaintext = T` | `RequiredContext<CallerContext>` (`RequiredContext<AeadContext>` with `context_type = AeadContext`) | the same | `value.encrypt_into_with_context(&keyset, nonempty!("users/email"))` |
| with a `context_field` of type `C` | `RequiredContext<NonEmpty<C>>` | `ExpectedContext<C>` | `T::decrypt_from(record, &cipher)` opens under the stored context; `decrypt_from_with_context(record, &cipher, nonempty!(..))` also checks it |

A `struct` record's field is handed its pair, extended by the caller's part
if one was given, so the field's target must accept a caller context: a
`Ciphertext` (`OptionalContext`), a term or an `Encrypted<Terms>`
(`RequiredContext<CallerContext>`), a `StackCipherText`
(`RequiredContext<AeadContext>`), a `plaintext` record, or another `struct`
record (whose own pairs the outer pair then extends). A target that declares
its whole context itself (`NoCallerContext`) or requires a context of another
type (`RequiredContext<u64>`) is refused at that field. A `#[stash(passthrough)]`
field is moved into the record by the owned conversion; its type is `Clone`
too, since the record's borrowed form, which a plan or a structural record
runs, copies it.

A `struct` record accounts for every field of its plaintext, sealing it or
carrying it through: the owned conversion destructures the struct, and a
field it does neither would be dropped unwiped, so it is refused at the
`struct = ..` path ("pattern does not mention field"). For the same reason
the plaintext struct cannot implement `Drop` (so not `ZeroizeOnDrop`
either): a type with a destructor cannot be destructured. A field's
declaration that panics wipes the sealed fields not yet handed to their
own declarations, and a record's declaration that panics while it is
constructed wipes the whole plaintext. On decryption a field opened before
a later field is refused is wiped, not dropped as it is.

A `plaintext` record's fields are all handed the one context the record
requires, so a term beside an `AeadContext`-only record is refused at the
term. Omitting a required context is refused at the call
(`AllowsNoContext`), whatever `Default` the context type has.

Both owned derives also emit the structural declarations: `EncryptTarget`
emits `EncryptFrom` (the record's legacy context — `DeclaredContext`,
`CallerContext` or `NonEmpty<C>` — converted into its owned input) and
`Decryptable`; `DecryptSource` emits `DecryptInto` and `DecryptField`. An
owned record is therefore a field of a `#[derive(EncryptFrom)]` struct
record and a typed field of a plan (`encrypt_into::<Record, _>`) without
a second derive. A hand-written owned target that is to be a record field
implements `Decryptable` and `DecryptField` beside `DecryptSource`.

```rust
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, StackCipher};

#[derive(Debug, PartialEq, zeroize::Zeroize)]
struct User { id: u64, name: String, email: String }

/// A searchable scalar: the ciphertext and an equality term, under the one
/// context the field (or a caller) supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail { ciphertext: Ciphertext, equality: EqualityTerm }

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct SearchableUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,        // ("users", "name")
    email: SearchableEmail,  // ("users", "email")
}

# tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
let cipher = StackCipher::builder()
    .kms(stack_encrypt::kms::FakeDataKeySource::new()).init().await?;
let keyset = cipher.default_keyset();
let users = vec![
    User { id: 42, name: "Alice".into(), email: "alice@example.com".into() },
    User { id: 43, name: "Bob".into(), email: "bob@example.com".into() },
];
// One batched key request for both rows' four sealed fields.
let rows: Vec<SearchableUser> = users.encrypt_into(&keyset).await?;
// A query term is the same derivation under the same context.
let wanted: EqualityTerm = String::from("alice@example.com")
    .encrypt_into_with_context(&keyset, stack_encrypt::nonempty!("users").with("email"))
    .await?;
let matched: Vec<SearchableUser> = rows.into_iter().filter(|r| r.email.equality == wanted).collect();
let opened = Vec::<User>::decrypt_from(matched, &cipher).await?;
assert_eq!(opened.len(), 1);
assert_eq!(opened[0].id, 42);
# Ok::<(), stack_encrypt::Error>(())
# }).unwrap();
```

## Which context a record takes

`CallerContext` holds both of Vitamin C's encodings of the context — the AEAD
one a ciphertext is sealed under and the PRF one a term is derived under — so
building it needs a `T` that is both `IntoAad` and `IntoPrfContext`. A record
made only of ciphertexts needs only the first, and the leaf it wraps
(`StackCipherText`) asks for only that: its context is `AeadContext`. Such a
record says so with `#[stash(context_type = AeadContext)]`, and then accepts
every context the canonical `keyset.encrypt_tree(value, context)` path accepts,
including a type that implements `IntoAad` alone:

```rust,no_run
use stack_encrypt::{DecryptInto, EncryptFrom, NonEmpty, StackCipherText};
use stack_encrypt::target::{AeadContext, legacy::EncryptInto};

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = AeadContext)]
struct SealedName {
    c: StackCipherText,
}

# async fn example<K: stack_encrypt::kms::DataKeySource + stack_encrypt::kms::IndexKeySource + Sync + 'static>(keyset: stack_encrypt::KeysetCipher<'_, K>, name: String, tenant: &str) -> Result<(), Box<dyn std::error::Error>> {
let record: SealedName = name.encrypt_into_with_context(&keyset, NonEmpty::new(tenant)?).await?;
# Ok(())
# }
```

The derive cannot pick this for you: it sees the field types' names, not
what they declare. The type you name must convert into every field's own
`Context` (`AeadContext` does not convert into `CallerContext`, so a term
field beside it is a compile error at the record, which is the point). A
record with a `context_field`, or a `struct` derive, settles its context
itself and refuses the attribute.

A declaration is executed by `keyset.encrypt_as(&value, context)` and
`cipher.decrypt_as(record, context)`, or through the blanket
`stack_encrypt::target::legacy::{EncryptInto, DecryptFrom}` traits for the source-side spelling (`value.encrypt_into(&keyset)`,
`record.decrypt_into(&cipher, context)`). A hand-written target implements the
same two declaration methods the derives emit, `EncryptFrom::encryption` and
`DecryptInto::decryption`; neither receives the plaintext or a cipher.

Every attribute except `plaintext` is singular, and repeating one is a
compile error rather than a silent overwrite (`plaintext` is repeatable,
but each listed type only once).

## Structs, field by field

A `struct = ..` derive needs no attribute on its fields. With
`#[stash(struct = User, context = "users")]`, a field `age` is derived from
`user.age` under the **pair** `("users", "age")` — two context parts, which
render the ZeroKMS descriptor `users/age`; a field `email` from `user.email`
under `("users", "email")`. The first part is the container's `context` and
the second the *plaintext* field's name. Both must be plain descriptor
segments (no `/`, `(`, `)`, control or invisible character; not beginning
with `b64:`, a digit or `-`), or the descriptor would render escaped and the
ZeroKMS log would not name the column: the derive refuses a prefix such as
`"public/users"` (write `"users"`), and a tuple field — whose index begins
with a digit — must name its segment with `identity = ".."`. So `#[stash(from = email_address)] email: ..` is derived under
`("users", "email_address")`: both parts name the stored field, not the
encrypted struct. Nothing is pluralised or otherwise guessed. The pair is
what `nonempty!("users").with("age")` spells at a call site, and what a
two-segment `Label` spells. `#[stash(identity = "nickname")] name: ..`
replaces the second part only: the field is derived under
`("users", "nickname")`. A field cannot be given a context of its own
(`context = ".."` on it is refused): it always sits under the record's. Each plaintext field has exactly one output, and each output
its own segment: a ciphertext with search terms beside it is one field of
type `Encrypted<Terms>` (`email: Encrypted<(EqualityTerm, MatchTerms)>`),
not a ciphertext field plus term fields `from` the same plaintext field. A
field whose type is itself a record (a `struct` derive, say)
is an ordinary field: it is handed its pair, and the inner record's own
fields sit under it, their contexts extended by it.

A context passed by the caller extends every field's: under
`user.encrypt_into_with_context(&keyset, 7u64)` the `age` field is derived
under `(("users", "age"), 7u64)`, and a query site probes it under
`nonempty!("users").with("age").with(7u64)`. This is how a field is bound to its
record as well as its name — a record id, say — without the type having to
know the id. Decryption takes the same extension. The extension may be borrowed at the call site: its Vitamin C encodings are
owned by the declaration before execution.

The context is part of the stored data's identity: it is the AAD of every
ciphertext in the column and the domain of every term. That is why the prefix
is required and explicit rather than inferred from the Rust type's name: two
plaintext types with the same name in different modules would otherwise
silently share every column context — equal plaintexts would produce
identical index terms across their tables, and ciphertexts would be
transplantable between them — and a rename would silently change the AAD of
everything stored. The field half *is* inferred from the plaintext field's
name, so renaming a plaintext field still changes that field's context and
stored data stops decrypting — `Error::Kms` against ZeroKMS, which refuses
the key retrieval under the changed descriptor before the AEAD runs, and
`Error::Aead` under a key source that ignores descriptors, such as the fake
one in tests — silently at the call site, with no compile-time signal.
Before such a rename, pin the old name as the field's segment with
`#[stash(identity = "old_name")]`, which keeps the pair
`("<context>", "old_name")` while the plaintext field moves.

A `struct` derive has no field derived from the whole plaintext, and a
`plaintext` record has none derived from a field of it: `from` and
`identity` exist only with `struct`, and the two container attributes are
exclusive.

## Which field decryption opens

`DecryptInto` does not need to be told: every field type says whether it is a
ciphertext or a one-way index term (`Decryptable`), and the derive requires
exactly one ciphertext — among all derived fields for a record, or in the
one field derived from each plaintext field for a `struct` derive. Too few or
too many is a compile error at the record's definition (at its first use, if
the record is generic). A derived record is itself `Decryptable` if any of
its fields is, so records nest in structs without ceremony; a type of your own
implements `Decryptable` and `DecryptField` by hand.

`decrypt` is the override for the shapes the types cannot settle: two
ciphertexts of which one is to be opened, or a field type that is not
`Decryptable`. Once any field is marked, only the marked fields are
considered — one opened as the whole plaintext, or several with `from = ..`
rebuilding the plaintext field by field — and the field types need not be
`Decryptable`. The record's own `Decryptable` impl (emitted by
`#[derive(EncryptFrom)]`) is then `true` outright — the marker says
decryption opens the record — so a marked record still nests in structs.

`DecryptInto` consumes the record, moving each opened field out of `self`, so
the record must not implement `Drop` (including via `ZeroizeOnDrop`); wrap the
fields that need zeroizing instead.

Terms open nothing, so a context handed to a term field on decrypt is
checked for nothing; the ciphertext field is what authenticates, under its
own context extended with the caller's exactly as it was sealed. A record
sealed with `encrypt_into` opens with `decrypt_from` and not under any
`NonEmpty<T>`; one sealed under an extension opens only under the same
extension.
