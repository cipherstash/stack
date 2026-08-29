# Attributes

All attributes live under `#[stash(...)]`.

## On the struct

| Attribute | Effect |
|---|---|
| `plaintext = Type` | The record is an encrypted form of `Type`. Repeatable: one impl per listed type. Omit it for an impl generic over the plaintext (see below). |
| `row = Type` | The record is a row of the struct `Type`: every derived field is derived from the plaintext field of its own name, under the context `"<type>/<field>"` (see [Rows](#rows)). Exclusive with `plaintext`. |
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

A row needs no attribute on its fields. With `row = User`, a field `age` is
derived from `user.age` under the context `"user/age"`; a field `email` from
`user.email` under `"user/email"`; a tuple row's `.0` under `"user/0"`. The
context is the plaintext type's last path segment in `snake_case`
(`UserProfile` → `"user_profile/age"`) and the *plaintext* field's name, so
`#[stash(from = email_address)] email: ..` is derived under
`"user_profile/email_address"`: both halves name the column, not the encrypted
struct. Nothing is pluralised or otherwise guessed. `context = ".."` on a
field is taken verbatim and replaces the inferred one.

The inferred context is part of the stored data's identity: it is the AAD of
every ciphertext in the column and the domain of every term. Renaming the
plaintext struct or a plaintext field therefore changes it, and rows already
stored stop decrypting (`Error::Aead`) — silently at the call site, with no
compile-time signal. Before renaming either, pin the old value with
`context = ".."` on the fields it reaches; or pin every context from the
start if the type's name is likely to move.

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
