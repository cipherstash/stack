---
"@cipherstash/auth": patch
---

The native binaries now use rustls 0.23.45, which fixes GHSA-2mjx-qc3c-rqvc
(affecting rustls 0.23.13 up to 0.23.44). The package's API is unchanged.
