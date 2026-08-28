# Attributes

All attributes live under `#[encrypted(...)]`.

## On the struct

| Attribute | Effect |
|---|---|
| `source = Type` | The record is an encrypted form of `Type`. Repeatable: one impl per listed type. Omit it for an impl generic over the source (see below). |
| `crate = "path"` | Where to find `stack_encrypt` in the generated code (default `::stack_encrypt`), for use through a re-export. |

Without `source`, `Encrypted` emits one impl generic over the source, bounded
so the record accepts exactly the sources *every* derived field accepts —
`EncryptedAge` below is `EncryptFrom<S, _>` for any `S` that both
`StackCipherText` and `EqualityTerm` accept. With `source`, the record accepts
only the listed types (a column that holds integers should not accept a
`String`), and `DecryptFrom` — which must name the plaintext type — becomes
possible.

## On a field

| Attribute | Effect |
|---|---|
| `context = "..."` | Derive this field under exactly this context rather than the one the caller passed for the record. A query-side term built under the same literal matches it. |
| `from = field` | Derive this field from `source.field` rather than from the whole source. Needs `source = ..` on the struct. |
| `default` / `default = expr` | Not derived: filled with `Default::default()` or `expr`. Never encrypted, never authenticated. |
| `decrypt` | Decryption opens this field (`DecryptFrom` only). One field opened as the whole plaintext, or several with `from = ..` rebuilding the source field by field. |

The record's own context reaches every derived field that has no `context`
of its own; if every field has one, the record's context is unused and the
caller may pass `()`.
