---
"@cipherstash/protect-ffi": patch
"@cipherstash/protect-ffi-darwin-arm64": patch
"@cipherstash/protect-ffi-darwin-x64": patch
"@cipherstash/protect-ffi-linux-arm64-gnu": patch
"@cipherstash/protect-ffi-linux-x64-gnu": patch
"@cipherstash/protect-ffi-linux-x64-musl": patch
"@cipherstash/protect-ffi-win32-x64-msvc": patch
---

The native binaries now use rustls 0.23.45, which fixes GHSA-2mjx-qc3c-rqvc
(affecting rustls 0.23.13 up to 0.23.44). The package's API is unchanged.
