---
'stash': patch
---

Correct the `stash-drizzle` skill: `inArray` / `notInArray` now encrypt the whole
list in a single `encryptQuery` batch crossing (the `bulkEncrypt`/concurrency
fallback was removed when v3 query operands moved to `encryptQuery` — #622). The
skill ships inside the `stash` tarball, so this keeps the bundled guidance in step
with the adapter's behaviour.
