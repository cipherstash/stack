---
"@cipherstash/stack": minor
---

Rename the encryption client's auth strategy config field from `config.strategy` to **`config.authStrategy`** to make its purpose clear, and expand the `Encryption()` TypeDoc with a full authentication and keysets walkthrough.

**`config.authStrategy`** is the new, documented field for supplying an auth strategy (`OidcFederationStrategy`, `AccessKeyStrategy`, or any `{ getToken() }` object). **`config.strategy` is retained as a deprecated alias** — passing it still works and forwards to the client, but logs a one-time runtime deprecation warning. When both are set, `authStrategy` wins (and the deprecation warning still fires so the leftover field gets cleaned up).

```ts
import { Encryption, OidcFederationStrategy } from "@cipherstash/stack"

const client = await Encryption({
  schemas: [users],
  config: {
    authStrategy: OidcFederationStrategy.create(workspaceCrn, () => getUserJwt()),
  },
})
```

**Migration:** rename `config.strategy` → `config.authStrategy`. No behavioural change beyond the deprecation warning; the field is forwarded to protect-ffi's `strategy` option exactly as before.

The `Encryption()` TypeDoc now documents the default `auto` strategy (env vars → local dev profile via `npx stash auth login`), the four `CS_*` production/CI variables, custom strategies (`AccessKeyStrategy`, `OidcFederationStrategy`), lock context, and keysets for multi-tenant isolation.

Note: the `@cipherstash/stack/wasm-inline` entry still uses `config.strategy`; aligning that entry point to `authStrategy` is tracked as a follow-up.
