---
"@cipherstash/protect-ffi": patch
"@cipherstash/protect-ffi-darwin-arm64": patch
"@cipherstash/protect-ffi-darwin-x64": patch
"@cipherstash/protect-ffi-linux-arm64-gnu": patch
"@cipherstash/protect-ffi-linux-x64-gnu": patch
"@cipherstash/protect-ffi-linux-x64-musl": patch
"@cipherstash/protect-ffi-win32-x64-msvc": patch
---

`newClient` now refuses a client key whose permutations are not valid, with
an error that names `clientKey` and `CS_CLIENT_KEY` (#1911). Before this
fix, one changed character in `CS_CLIENT_KEY` could make `newClient` run at
full CPU and never settle, or panic. The key was accepted when it was read,
and the problem started only when the first key was derived, after the
ZeroKMS request.

A client key read from the profile store (`secretkey.json`) gets the same
check. The error names no value from the key.
