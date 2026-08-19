---
'@cipherstash/protect-ffi-darwin-x64': patch
'@cipherstash/protect-ffi-darwin-arm64': patch
'@cipherstash/protect-ffi-win32-x64-msvc': patch
'@cipherstash/protect-ffi-linux-x64-gnu': patch
'@cipherstash/protect-ffi-linux-arm64-gnu': patch
'@cipherstash/protect-ffi-linux-x64-musl': patch
---

**This is the first release of these packages published from
`cipherstash/stack`.** Every version up to and including 0.31.0 was published
from `cipherstash/protectjs-ffi`, which is now archived.

If you verify npm provenance, the attested source repository changes with this
release:

```
0.31.0   github.com/cipherstash/protectjs-ffi   .github/workflows/release.yml
0.32.0   github.com/cipherstash/stack           .github/workflows/release.yml
```

A verification policy that pins the source repository will reject 0.32.0 until
it is updated. The packages, their contents and their maintainers are otherwise
unchanged — the Rust source moved into the monorepo at
`packages/protect-ffi/crates/protect-ffi`, and each platform package's
`repository.url` and `repository.directory` now point there.

The binaries themselves also differ from 0.31.0 in one user-visible way: the
Rust core's `InvariantViolation` message asks the reader to file an issue, and
the repository it names has moved with the rest.
