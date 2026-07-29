---
'@cipherstash/stack': patch
---

Correct the `config.keyset` docs on what omitting the option resolves to.

The `Encryption()` and `ClientConfig.keyset` doc comments said omitting
`config.keyset` uses "the workspace's default keyset". The actual resolution
is the **client's** default keyset — the keyset the ZeroKMS client behind
your credentials was created against. The two coincide when the client was
created without naming a keyset — as with the profile credentials in a dev
environment — but a client created against a named keyset defaults to that
keyset, so two processes that both omit `config.keyset` share a keyspace
only if their clients default to the same keyset. The docs now say exactly
that.
