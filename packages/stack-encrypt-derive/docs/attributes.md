# Attributes

All attributes live under `#[stack_encrypt(...)]`.

## On the struct

| Attribute | Effect |
|---|---|
| `plaintext = Type` | The record is an encrypted form of `Type`. Repeatable: one impl per listed type. Omit it for an impl generic over the plaintext (see below). |
| `crate = "path"` | Where to find `stack_encrypt` in the generated code (default `::stack_encrypt`), for use through a re-export. |

`plaintext` must be an owned type: the generated impl has no lifetime to give
a reference. Without `plaintext`, each derive emits one impl generic over the plaintext,
bounded by what the fields accept: `EncryptedAge` below is `EncryptFrom<P, _>`
for any `P` that both `StackCipherText` and `EqualityTerm` accept, and
`DecryptInto<P, _>` for any `P` its `decrypt` field opens to. With
`plaintext`, the record accepts only the listed types (a column that holds
integers should not accept a `String`). Rows — decrypted field by field —
must name it: the plaintext is rebuilt with a struct literal.

## On a field

| Attribute | Effect |
|---|---|
| `context = "..."` | Derive this field under exactly this context rather than the one the caller passed for the record. A query-side term built under the same literal matches it. Must not be empty. |
| `from = field` / `from = 0` | Derive this field from `plaintext.field` (or `plaintext.0` for a tuple struct) rather than from the whole plaintext. Needs `plaintext = ..` on the struct. |
| `default` / `default = expr` | Not derived: filled with `Default::default()` or `expr`. Never encrypted, never authenticated. |
| `decrypt` | Decryption opens this field (`DecryptInto` only). One field opened as the whole plaintext, or several with `from = ..` rebuilding the plaintext field by field. |

The record's own context reaches every derived field that has no `context`
of its own; if every field has one, the record's context is unused and the
caller may pass `()`.

`DecryptInto` consumes the record, moving each opened field out of `self`, so
the record must not implement `Drop` (including via `ZeroizeOnDrop`); wrap the
fields that need zeroizing instead.
