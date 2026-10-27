---
"@cipherstash/auth": patch
---

The native binaries now refuse a TLS certificate chain that carries one of the
eight eMudhra intermediate CA keys reported compromised on 2026-10-17, including
their Sectigo cross-signs. On Linux the platform verifier checks no revocation,
so these intermediates were still trusted through the distro CA bundle. Such a
chain now fails as a revoked certificate. The package's API is unchanged, and
the WASM build is unaffected because the runtime's `fetch` handles TLS there.
