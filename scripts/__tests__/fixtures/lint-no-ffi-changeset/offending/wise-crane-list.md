---
'@cipherstash/stack': patch
'@cipherstash/protect-ffi-darwin-arm64': patch
---

Two packages in one block — what `pnpm changeset` writes when you select more
than one. The FFI package is deliberately NOT the first line: the package you
set out to change gets picked first, so this is the ordinary shape of the
mistake this guard exists to catch, not an exotic one.
