---
"@cipherstash/eql": minor
---

**Stack Encrypt can now write EQL v4's storage-only JSON type, `Json` (`public.eql_v4_json`).** A `Json` value stores a JSON document as one ciphertext, with no index: `{v, i, c}`, where `c` holds the document's JSON text sealed as one text leaf. It shows the size of the document and nothing else. Use it for a document that is stored and read back whole. `JsonSearch` stays the type for a document that is searched.

`eql-bindings` (the Rust crate released with this package):

- `v4::json::Json` implements `EncryptTarget` and `DecryptSource` for `v4::plaintext::JsonPlaintext`, and for an `Option` of it. `JsonPlaintext` is Stack Encrypt's wipeable JSON document (`stack_encrypt::json::JsonPlaintext`): build it with `JsonPlaintext::from(value)` or `JsonPlaintext::parse(text)`.
- The target table lists `Json` as producible, with the plaintext kind `json`, no index and no query. The by-name dispatch (`encryption::targets`) seals a document handed over as UTF-8 JSON text, in a text or bytes value, and opens it back to its text. Text that is not a document by Stack Encrypt's rules is refused before any key is requested (`TargetError::Json`, with a code and none of the text).
- On decrypt, a `c` that opens but does not hold JSON text is `Error::OpenedType`: the value was sealed as another type.
- The Go type `eql.JSON` is listed as producible too.

Before, the table marked `Json` as not producible, because how a document becomes one sealed leaf was not decided. The SQL bundle and the TypeScript types do not change.
