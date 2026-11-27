---
'@cipherstash/eql': patch
---

**Two eql-bindings errors no longer show a field's label, and one no longer quotes stored bytes** (`stack-encrypt` feature, #1999). A label is an encryption context. `TargetError::Context` and `QueryLabelError::NotAColumn` no longer show it. On the data path, `stack-encrypt`'s `TargetError::Column` still shows the label until #1983 lands.

- `encryption::targets::TargetError::Context` was `"app/users/email" is not an EQL column identifier: expected two segments, table and column`. It is now `the field's label is not an EQL column identifier: expected two segments, table and column`.
- `encryption::query::QueryLabelError::NotAColumn` now starts `the query's label is not an EQL column identifier`. A typed query returns it inside `stack_encrypt::Error::Other`.
- `Debug` shows the label of both errors as `<redacted>`. Both types now write `Debug` by hand.
- Both variants keep their `label` field, so code that builds or matches them still compiles. Code that needs the label takes it from the plan or the query.
- `encryption::targets::TargetError::Stored` now shows only the kind, line, and column of the JSON parser's error, in its message and in `Debug`. The parser's own message could quote the stored ciphertext it refused. For example: `stored value is not a TextEq: unexpected data at line 1 column 19`. Its `source` field and `source()` still return the parser's error.
- `TargetError` prints every other variant in `Debug` as the derived `Debug` did.
