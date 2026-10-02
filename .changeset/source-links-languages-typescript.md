---
"@cipherstash/migrate": patch
"@cipherstash/nextjs": patch
"@cipherstash/protect-ffi": patch
"@cipherstash/protect-ffi-darwin-arm64": patch
"@cipherstash/protect-ffi-darwin-x64": patch
"@cipherstash/protect-ffi-linux-arm64-gnu": patch
"@cipherstash/protect-ffi-linux-x64-gnu": patch
"@cipherstash/protect-ffi-linux-x64-musl": patch
"@cipherstash/protect-ffi-win32-x64-msvc": patch
---

The package's source links now point at its folder under
`languages/typescript/` in cipherstash/stack. The previous release linked to
its old folder under `packages/`, which no longer exists, so the README's
source links and the npm page's repository link returned 404.
