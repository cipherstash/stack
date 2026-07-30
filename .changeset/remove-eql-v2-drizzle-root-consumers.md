---
'stash': patch
'@cipherstash/stack': patch
---

Follow the `@cipherstash/stack-drizzle` package-root collapse in the packages that
document it.

- **`stash`:** `stash init --drizzle` emits the package-root
  `extractEncryptionSchema` import, and the bundled `stash-drizzle` and
  `stash-encryption` skills match.
- **`@cipherstash/stack`:** README only — its Drizzle section documents the
  package-root exports.
