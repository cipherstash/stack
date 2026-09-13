# Attributes

All attributes live under `#[stash(...)]`.

## On the struct

| Attribute | Effect |
|---|---|
| `plaintext = Type` | The record is an encrypted form of `Type`, every field derived from the whole value. Repeatable: one impl per listed type. Omit it for an impl generic over the plaintext (see below). |
| `struct = Type` | The record encrypts the struct `Type` field by field: every derived field is derived from the plaintext field of its own name, under the context `"<context>/<field>"` (see [Structs, field by field](#structs-field-by-field)). Exclusive with `plaintext`; requires `context`. |
| `context = "..."` | With `struct` only: the first half of every field's inferred context — the stored data's name. Required, never inferred from the type's name, and must not be empty. |
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
| `context_field` | Store the caller’s typed context here and recover it on decryption. Exactly one per record; excludes the other field attributes and literal contexts. |
| `context = "..."` | Derive this field under exactly this context, extended by the one the caller passes for the record like any other. A query-side term built under the same literal — extended the same way — matches it. Must not be empty. |
| `from = field` / `from = 0` | With `struct` only: derive this field from `plaintext.field` (or `plaintext.0` for a tuple struct) when its name differs from its plaintext field's. |
| `default` / `default = expr` | Not derived: filled with `Default::default()` or `expr`. Never encrypted, never authenticated. |
| `decrypt` | Decryption opens this field (`DecryptInto` only). Needed only when the field types cannot decide it — see below. |
| `nested` | With `struct` only: infer no context for this field — it is handed the caller's context as it is, which its type (a nested `struct` derive carrying its own contexts) composes with them. Excludes `context`. |

Each derive emits one declaration per plaintext, with an associated `Context`.
A record with `#[stash(context_field)]` on a field of type `T` requires
`NonEmpty<T>` for encryption and stores its inner value in that field. Decryption
takes `ExpectedContext<T>`: its default reads and validates the stored value;
`NonEmpty<T>.into()` also checks it against the expected destination before key
retrieval. `T` supplies the Vitamin C context encodings and implements `Clone`,
`MaybeEmpty`, and `PartialEq`. This metadata is not a separate encrypted field.
It cannot be combined with literal context attributes.

Otherwise, a record whose fields all carry their own contexts (including a
`struct` derive) uses `DeclaredContext`. `().into()` or its default selects the
declared contexts unchanged; a nonempty caller context extends each base context.
A record with fields that need a caller context uses `CallerContext`, constructed
from a `NonEmpty<T>` or a supported integer. Both encodings and the descriptor's
structured identity are preserved when borrowing context data is converted into
an owned declaration. No context is inferred from a Rust type's name.

The blanket `EncryptInto` and `DecryptFrom` convenience traits execute these
declarations. Import `DecryptFrom` to call `.decrypt_into(...)`. Custom targets
implement the declaration methods `encryption` and `decryption`; the old methods
that received plaintext and a cipher are no longer extension points.

Every attribute except `plaintext` is singular, and repeating one is a
compile error rather than a silent overwrite (`plaintext` is repeatable,
but each listed type only once).

## Structs, field by field

A `struct = ..` derive needs no attribute on its fields. With
`#[stash(struct = User, context = "users")]`, a field `age` is derived from
`user.age` under the context `"users/age"`; a field `email` from `user.email`
under `"users/email"`; a tuple struct's `.0` under `"users/0"`. The first
half is the container's `context` and the second the *plaintext* field's
name, so `#[stash(from = email_address)] email: ..` is derived under
`"users/email_address"`: both halves name the stored field, not the
encrypted struct. Nothing is pluralised or otherwise guessed. `context =
".."` on a field is taken verbatim and replaces the inferred one; `nested`
on a field infers none — the field is handed the caller's context as it is,
which a nested `struct` derive (carrying its own contexts) composes with
them and a leaf accepts only as a `NonEmpty<T>`.

A context passed by the caller extends every field's: under
`user.encrypt_into_with_context(&keyset, 7u64)` the `age` field is derived
under `("users/age", 7u64)`, and a query site probes it under
`nonempty!("users/age").with(7u64)`. This is how a field is bound to its
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
Before such a rename, pin the old value with `context = ".."` on the fields
it reaches.

A `struct` derive has no field derived from the whole plaintext, and a
`plaintext` record has none derived from a field of it: `from` and `nested`
exist only with `struct`, and the two container attributes are exclusive.

## Which field decryption opens

`DecryptInto` does not need to be told: every field type says whether it is a
ciphertext or a one-way index term (`Decryptable`), and the derive requires
exactly one ciphertext — among all derived fields for a record, or among the
fields derived from each plaintext field for a `struct` derive. Too few or
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
