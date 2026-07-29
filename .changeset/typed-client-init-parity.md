---
'@cipherstash/stack': patch
---

`Encryption` now exposes one EQL v3-only construction path and returns
`EncryptionClient<S>` consistently for the supplied schemas:

```ts
const config: ClientConfig = { keyset }
const client = await Encryption({ schemas: [users], config })
// type and runtime share the same generic EncryptionClient<S> surface
```

The public client no longer exposes a separate `init` method or a config option
that can select EQL v2. Initialization happens through `Encryption`, which
always configures EQL v3 and prevents the former type/runtime split.
