---
"@cipherstash/auth": patch
---

The `linux-x64-musl` binary now links musl. In 0.44.0 it linked glibc, so
`@cipherstash/auth` did not load on musl systems such as Alpine Linux.
