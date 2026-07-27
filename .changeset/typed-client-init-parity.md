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
so any call through the declared type crashed. It is now present — and pins the
wire format rather than delegating verbatim.

That distinction matters. `EncryptionClient.init` takes its own `eqlVersion` and
forwards `undefined` to the FFI, whose default is EQL **v2**, and it never
consults the check `Encryption` runs at construction. A bare passthrough would
therefore have let a typed v3 client be re-initialised into v2 wire while keeping
its v3 surface — writing `eql_v2_encrypted` payloads into `eql_v3_*` columns, the
same contradiction refused at construction, one method call later. The typed
`init` pins `eqlVersion: 3`, refuses an explicit `2` with a failure `Result`, and
resolves to the **typed** client, so the common
`client = (await client.init(cfg)).data` does not silently swap the typed surface
for the nominal one.

The type still under-reports in this case: you lose the typed surface with no
diagnostic. Pass the config inline, or type the variable as `V3ClientConfig`, to
keep it.
