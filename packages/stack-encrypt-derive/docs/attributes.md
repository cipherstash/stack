# Attributes

All attributes are written inside `#[stash(...)]`. The four derives read the
same attributes:

- `EncryptTarget` and `DecryptSource` declare a record the owned way. The
  caller passes the plaintext by value. Encrypting it consumes it and wipes
  it.
  Only these two derives accept `passthrough`. Each also implements the
  structural traits, so the record works where a structural one is expected.
- `EncryptFrom` and `DecryptInto` declare a record the structural way, over
  a borrowed plaintext.

Derive one pair on a record, not both.

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
| `passthrough` | Owned derives, with `struct` only: move the plaintext field of the same name (or the one `from = field` names) into the record as it is, and move it back on decryption. **Not encrypted and not authenticated**: see [Passthrough fields](#passthrough-fields). The field has no context. Cannot be combined with `identity`, `default` or `decrypt`. |

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

`#[derive(EncryptTarget, DecryptSource)]` takes the attributes above.
`value.encrypt_into(&keyset)` consumes the plaintext and wipes each field it
seals, and `Plaintext::decrypt_from(record, &cipher)` returns the plaintext.
The plaintext type must implement `Zeroize`.

### What the caller passes

The record's `ContextInput` decides which context a caller can pass, and
which context the caller must pass:

| Record | Encrypt input | Decrypt input | Example call |
|---|---|---|---|
| `struct = User, context = "users"` | `ContextExtension<DeclaredContext>` | The same as for encryption | `user.encrypt_into(&keyset)`, or `user.encrypt_into_with_context(&keyset, 7u64)` to extend every field's context with the row id `7` |
| `plaintext = T` | `RequiredContext<CallerContext>`, or `RequiredContext<AeadContext>` with `context_type = AeadContext` | The same as for encryption | `value.encrypt_into_with_context(&keyset, nonempty!("users/email"))` |
| With a `context_field` of type `C` | `RequiredContext<NonEmpty<C>>` | `ExpectedContext<C>` | `T::decrypt_from_with_context(record, &cipher, nonempty!(..))`, which checks the stored context before it decrypts |

A `context_field` record can also be opened with `T::decrypt_from(record,
&cipher)`, with no context. That call opens the record under whatever
context it stores, and checks only that the context is not empty. The
stored context is not authenticated, so a ciphertext moved together with its
stored context opens in its new place. Pass the context you expect, unless
you have checked the record's place some other way.

### Fields of a `struct` record

Each field of a `struct` record is given its context, `("users", "<field>")`,
extended by the caller's context if there is one. So the field's target must
accept a context from the record. These targets accept one:

- `Ciphertext`, whose input is `OptionalContext`.
- A term, or an `Encrypted<Terms>`, whose input is
  `RequiredContext<CallerContext>`.
- `StackCipherText`, whose input is `RequiredContext<AeadContext>`.
- A `plaintext` record.
- Another `struct` record. The outer field's context then extends the
  inner record's own contexts.

Two kinds of target are a compile error at the field. One kind builds its
whole context itself (`NoCallerContext`). The other requires a context of
another type, such as `RequiredContext<u64>`.

The record must name every field of its plaintext, as a sealed field or a
passthrough field. The owned conversion moves the fields out of the
plaintext struct, and a field it did not name would be dropped without
being wiped. So a field that is left out is a compile error at the
`struct = ..` path ("pattern does not mention field").

### Passthrough fields

A `#[stash(passthrough)]` field is moved from the plaintext into the record,
and back again on decryption. A passthrough field is **not encrypted and
not authenticated**.
Anyone with access to the stored record can read the value, change it or
remove it, and every sealed field beside it still decrypts.

- Use a passthrough field only for a value that is not secret.
- Treat the value you read back as untrusted input. Never let it decide
  authorisation, tenancy, or which record to trust.
- Do not use a passthrough field for a value that must be readable and
  also tamper-evident. Pass that value as the caller's context instead, as
  the row id is passed above. A changed context makes decryption fail.

The owned conversion never copies a passthrough field. The field's type
must still implement `Clone`, because the structural form of the record
copies it. Plans and structural records run that form.

### Wiping

- The conversion wipes each sealed field before the pending request is
  returned.
- If a field's declaration panics, the sealed fields that are still waiting
  for their own declarations are wiped.
- If the record's declaration panics while it is being built, the whole
  plaintext is wiped.
- On decryption, if a later field is refused, the fields already opened are
  wiped before the error is returned.

**A decrypted plaintext is not wiped when it is dropped.** The derive moves
the fields out of the plaintext struct, and Rust does not allow that for a
type that implements `Drop`. So the plaintext type cannot derive
`ZeroizeOnDrop`. Wrap a decrypted value in `stack_encrypt::Protected` as
soon as it is returned, or call `zeroize` on it when you no longer need it.
Do not derive these traits on the plaintext type either:

- `Debug`, because it prints the plaintext.
- `Clone`, because each clone is another copy to wipe.
- `PartialEq`, because a derived comparison does not run in constant time.

### Fields of a `plaintext` record

Every field of a `plaintext` record is given the one context the record
requires. So a term field in a record with `context_type = AeadContext` is a
compile error at the term, because a term needs a `CallerContext`. A call
that leaves out a required context is a compile error at the call
(`AllowsNoContext`), even if the context type implements `Default`.

### The structural traits

Each owned derive also implements the structural traits:

- `EncryptTarget` also implements `EncryptFrom` and `Decryptable`.
  `EncryptFrom` converts the record's structural context into the owned
  input. The structural context is a `DeclaredContext`, a `CallerContext`,
  or a `NonEmpty<C>`.
- `DecryptSource` also implements `DecryptInto` and `DecryptField`.

So an owned record can be a field of a `#[derive(EncryptFrom)]` record, or a
typed field of a plan (`encrypt_into::<Record, _>`), with no second derive.
A hand-written owned target that will be a record field must implement
`Decryptable` and `DecryptField`, as well as `DecryptSource`.

### Example

```rust
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, Controlled, DecryptFrom, EncryptInto, Protected, StackCipher};

// The plaintext derives `Zeroize` and nothing else.
#[derive(zeroize::Zeroize)]
struct User { id: u64, name: String, email: String }

/// An email address you can search for: its ciphertext and an equality
/// term, under the one context that the record field supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail { ciphertext: Ciphertext, equality: EqualityTerm }

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct SearchableUser {
    // Not encrypted and not authenticated.
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,        // sealed under ("users", "name")
    email: SearchableEmail,  // derived under ("users", "email")
}

# tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
// With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
// the environment, or from the profile that `npx stash auth login` writes.
let cipher = StackCipher::builder()
#     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    .init()
    .await?;
let keyset = cipher.default_keyset();
let users = vec![
    User { id: 42, name: "Alice".into(), email: "alice@example.com".into() },
    User { id: 43, name: "Bob".into(), email: "bob@example.com".into() },
];
// One batched key request seals the four sealed fields of both rows.
let rows: Vec<SearchableUser> = users.encrypt_into(&keyset).await?;

// A query term is the same derivation, under the same context.
let wanted: EqualityTerm = String::from("alice@example.com")
    .encrypt_into_with_context(&keyset, stack_encrypt::nonempty!("users").with("email"))
    .await?;
let matched: Vec<SearchableUser> = rows.into_iter().filter(|r| r.email.equality == wanted).collect();

// Wrap the decrypted users at once. `Protected` wipes them when it is dropped.
let opened = Protected::new(Vec::<User>::decrypt_from(matched, &cipher).await?);
assert_eq!(opened.risky_ref().len(), 1);
assert_eq!(opened.risky_ref()[0].id, 42);
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
