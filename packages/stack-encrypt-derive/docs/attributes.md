# Attributes

All attributes live under `#[stash(...)]`.

## On the struct

| Attribute | Effect |
|---|---|
| `plaintext = Type` | The record is an encrypted form of `Type`. Repeatable: one impl per listed type. Omit it for an impl generic over the plaintext (see below). |
| `row = Type` | The record is a row of the struct `Type`: every derived field is derived from the plaintext field of its own name, under the context `"<context>/<field>"` (see [Rows](#rows)). Exclusive with `plaintext`; requires `context`. |
| `context = "..."` | With `row` only: the first half of every field's inferred context — the table's name. Required, never inferred from the type's name, and must not be empty. |
| `crate = "path"` | Where to find `stack_encrypt` in the generated code (default `::stack_encrypt`), for use through a re-export. |

`plaintext` must be an owned type: the generated impl has no lifetime to give
a reference. Without `plaintext`, each derive emits one impl generic over the plaintext,
bounded by what the fields accept: `EncryptedAge` below is `EncryptFrom<P, _, _>`
for any `P` that both `StackCipherText` and `EqualityTerm` accept, and
`DecryptInto<P, _, _>` for any `P` its `decrypt` field opens to. With
`plaintext`, the record accepts only the listed types (a column that holds
integers should not accept a `String`). Rows — decrypted field by field —
must name it: the plaintext is rebuilt with a struct literal.

## On a field

| Attribute | Effect |
|---|---|
| `context = "..."` | Derive this field under exactly this context rather than the one the caller passes for the record. A query-side term built under the same literal matches it. Must not be empty. |
| `from = field` / `from = 0` | Derive this field from `plaintext.field` (or `plaintext.0` for a tuple struct) rather than from the whole plaintext. Needs `plaintext = ..` or `row = ..` on the struct; in a row, only for a field whose name differs from its plaintext field's. |
| `default` / `default = expr` | Not derived: filled with `Default::default()` or `expr`. Never encrypted, never authenticated. |
| `decrypt` | Decryption opens this field (`DecryptInto` only). Needed only when the field types cannot decide it — see below. |
| `nested` | In a row only: infer no context for this field — it is handed `()`, which its type (a nested row carrying its own contexts) accepts and a leaf refuses. Excludes `context`. |

The caller's context reaches every field derived from the whole plaintext
that has no `context` of its own, and the impl's context parameter is bounded
by what those fields accept — a leaf accepts only a `SuppliedContext`, so a
record that hands the caller's context to one is encrypted with
`encrypt_into_with_context`. A `from` field never receives the caller's
context: it is derived under its `context`, or under `()` if it has none,
which a nested row accepts and a leaf refuses (at the field, until it is
given a `context`). A record none of whose fields takes the caller's context
— every row — is implemented for `()` exactly, and is encrypted with the
context-free `encrypt_into` (decrypted with
`Plaintext::decrypt_from(record, &cipher)`); the compiler turns the other
form away, since the context would go nowhere.

Every attribute except `plaintext` is singular, and repeating one is a
compile error rather than a silent overwrite (`plaintext` is repeatable,
but each listed type only once).

## Rows

A row needs no attribute on its fields. With
`#[stash(row = User, context = "users")]`, a field `age` is derived from
`user.age` under the context `"users/age"`; a field `email` from `user.email`
under `"users/email"`; a tuple row's `.0` under `"users/0"`. The first half
is the container's `context` and the second the *plaintext* field's name, so
`#[stash(from = email_address)] email: ..` is derived under
`"users/email_address"`: both halves name the column, not the encrypted
struct. Nothing is pluralised or otherwise guessed. `context = ".."` on a
field is taken verbatim and replaces the inferred one; `nested` on a field
infers none — the field is handed `()`, which is what a nested row (its own
`row = ..` derive, carrying its own contexts) accepts and a leaf refuses.

The context is part of the stored data's identity: it is the AAD of every
ciphertext in the column and the domain of every term. That is why the prefix
is required and explicit rather than inferred from the Rust type's name: two
plaintext types with the same name in different modules would otherwise
silently share every column context — equal plaintexts would produce
identical index terms across their tables, and ciphertexts would be
transplantable between them — and a rename would silently change the AAD of
every stored row. The field half *is* inferred from the plaintext field's
name, so renaming a plaintext field still changes that column's context and
stored rows stop decrypting (`Error::Aead`) — silently at the call site, with
no compile-time signal. Before such a rename, pin the old value with
`context = ".."` on the fields it reaches.

A row has no field derived from the whole plaintext; every derived field has
a `from`. Use `plaintext = ..` with explicit `from`s for a record that mixes
the two.

## Which field decryption opens

`DecryptInto` does not need to be told: every field type says whether it is a
ciphertext or a one-way index term (`Decryptable`), and the derive requires
exactly one ciphertext — among all derived fields for a record, or among the
fields derived from each plaintext field (`from = ..`) for a row. Too few or
too many is a compile error at the record's definition (at its first use, if
the record is generic). A derived record is itself `Decryptable` if any of
its fields is, so records nest in rows without ceremony; a type of your own
implements `Decryptable` and `DecryptField` by hand.

`decrypt` is the override for the shapes the types cannot settle: two
ciphertexts of which one is to be opened, or a field type that is not
`Decryptable`. Once any field is marked, only the marked fields are
considered — one opened as the whole plaintext, or several with `from = ..`
rebuilding the plaintext field by field — and the field types need not be
`Decryptable`. The record's own `Decryptable` impl (emitted by
`#[derive(EncryptFrom)]`) is then `true` outright — the marker says
decryption opens the record — so a marked record still nests in rows.

`DecryptInto` consumes the record, moving each opened field out of `self`, so
the record must not implement `Drop` (including via `ZeroizeOnDrop`); wrap the
fields that need zeroizing instead.

One asymmetry to know about: when the ciphertext field carries a `context`
literal, the record's `decrypt_into` still takes a caller context — the term
fields nominally receive it — but no field actually uses it: terms open
nothing, and the ciphertext authenticates under its literal. Decryption then
succeeds under *any* well-typed context, so a wrong caller context is not the
`Error::Aead` it would be against a leaf. Do not use the decrypt context as a
tenancy or sanity check on such a record; the authenticated context is the
field's literal.
