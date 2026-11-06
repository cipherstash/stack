---
'@cipherstash/auth': patch
---

No change to the binding. The `stack-kms-vendor` crate that it compiles in has a new test-only module, `replay`, behind its `test-support` feature. The binding does not turn on that feature, so the module is not in the binary.
