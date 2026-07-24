---
'@cipherstash/stack': patch
---

The typed EQL v3 client no longer throws `TypeError: init is not a function`.

`Encryption` selects its overload from the `config` argument but selects the
client it actually returns by inspecting the `schemas`, so the two can disagree.
Hoisting a config into a `ClientConfig`-typed variable is enough to split them —
`ClientConfig.eqlVersion` is `2 | 3`, which the v3 overload's `eqlVersion?: 3`
rejects — so the call types as the nominal `EncryptionClient` while the runtime
still returns the typed client:

```ts
const config: ClientConfig = { keyset }
const client = await Encryption({ schemas: [users], config })
// type: EncryptionClient · runtime: TypedEncryptionClient
```

`init` was the only member of `EncryptionClient` missing from the typed client,
so any call through the declared type crashed. It is now delegated.

The type still under-reports in this case: you lose the typed surface with no
diagnostic. Pass the config inline, or type the variable as `V3ClientConfig`, to
keep it.
