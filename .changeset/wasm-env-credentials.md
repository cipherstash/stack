---
'@cipherstash/stack': minor
---

`@cipherstash/stack/wasm-inline`: credentials now fall back to the environment.

The native entry has always resolved an omitted credential from `CS_*` env vars
or `~/.cipherstash`. The WASM entry had no fallback at all, so every edge caller
plumbed four values by hand even in Deno, Node, and Bun where the environment is
right there.

`config` is now optional, and each field falls back individually:

| Field | Environment variable |
| --- | --- |
| `clientId` | `CS_CLIENT_ID` |
| `clientKey` | `CS_CLIENT_KEY` |
| `workspaceCrn` | `CS_WORKSPACE_CRN` |
| `accessKey` | `CS_CLIENT_ACCESS_KEY` (or `CS_ACCESS_KEY`) |

```typescript
// Deno / Node / Bun, with the four CS_* vars set
const client = await Encryption({ schemas: [users] })
```

An explicit config value always wins — the environment only fills gaps — so
nothing changes for callers passing a full config today. `clientId` and
`clientKey` are read as a **pair**: setting only one env var fills neither,
matching the native reader, so a stale half-pair cannot silently combine with a
config value into a mismatched client.

**This needs a `process.env`, so it works in Deno, Node, and Bun but not in
Cloudflare Workers or browsers.** Workers hand their environment to the fetch
handler rather than exposing a global — read it there and pass the values on
`config`. Missing-credential errors now name the field, the environment variable
that would have supplied it, and say when the runtime has no environment to read
at all.

Do not rely on the fallback in browser-targeted builds: bundlers commonly inline
`process.env` at build time, which would bake the access key into client-side
JavaScript. Pass a pre-built `authStrategy` instead.
