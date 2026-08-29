# Attributes

All attributes live under `#[stash(...)]`.

## On the struct

| Attribute | Effect |
|---|---|
| `plaintext = Type` | The record is an encrypted form of `Type`. Repeatable: one impl per listed type. Omit it for an impl generic over the plaintext (see below). |
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
| `from = field` / `from = 0` | Derive this field from `plaintext.field` (or `plaintext.0` for a tuple struct) rather than from the whole plaintext. Needs `plaintext = ..` on the struct. |
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
