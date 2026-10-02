---
"@cipherstash/auth": patch
---

Internal restructuring of the underlying Rust crate: every strategy now sends
its requests through an `HttpTransport` trait, with the bundled reqwest client
as the default implementation, so the same strategies can run over a host's own
HTTP client (the Go binding's WASI guest). The npm builds always use the bundled
client — no API or behaviour change for `@cipherstash/auth` consumers.
