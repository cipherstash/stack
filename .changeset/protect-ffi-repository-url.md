---
'@cipherstash/protect-ffi': patch
---

Point the published metadata at `cipherstash/stack`, the repository these
packages are now built and published from. The wrapper's `repository.url`,
`bugs.url` and `homepage`, and each platform package's `repository.url`, all
named `cipherstash/protectjs-ffi`; each platform package's
`repository.directory` also named `platforms/<platform>`, which resolves from
the root of the repository named above and so addressed nothing here.

npm requires `repository.url` to match the publishing repository exactly for a
trusted publish, and rejects a mismatch rather than warning about it. A stale
`repository.directory` fails more quietly: the publish succeeds and the source
link on the package page 404s.

The one repository URL that reaches an end user at runtime moves too — the Rust
core's `InvariantViolation` error asks the reader to file an issue, and the
repository it pointed at is archived at the end of the publishing cutover.
