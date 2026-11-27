---
'@cipherstash/eql': patch
---

**eql-bindings no longer shows a field's label in a column refusal** (`stack-encrypt` feature, #1999). A label is an encryption context, and an error never shows the value of a context.

- `encryption::targets::TargetError::Context` was `"app/users/email" is not an EQL column identifier: expected two segments, table and column`. It is now `the field's label is not an EQL column identifier: expected two segments, table and column`.
- `encryption::query::QueryLabelError::NotAColumn` now starts `the query's label is not an EQL column identifier`. A typed query returns it inside `stack_encrypt::Error::Other`.
- `Debug` shows the label of both errors as `<redacted>`. Both types now write `Debug` by hand. `TargetError` prints every other variant as the derived `Debug` did.
- Both variants keep their `label` field, so code that builds or matches them still compiles. Code that needs the label takes it from the plan or the query.
