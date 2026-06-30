---
"@cipherstash/stack": minor
---

Bump `@cipherstash/protect-ffi` to `0.26.0` and `@cipherstash/auth` to `0.40.0`, and replace the lock-context token ceremony with a strategy-based approach for identity-bound encryption.

**protect-ffi `0.26.0`** supersedes `0.25.0`. The public API is unchanged from `0.25` (internal fixes only). As in `0.25`, `serviceToken` is gone from the encrypt / decrypt / query option types; auth flows through the client's strategy / credentials, and lock contexts travel as `lockContext.identityClaim`. The WASM-inline path takes a single options object with the auth strategy nested under `strategy`, and `Encryption()` config uses **`workspaceCrn`** (`CS_WORKSPACE_CRN`) as the single source of truth — `CS_REGION` is no longer consulted. On that path `workspaceCrn` is required only alongside an `accessKey` (it derives the region); with a pre-built `strategy` it is **optional**, since the strategy already carries the CRN.

**Strategy-based, identity-bound encryption.** `OidcFederationStrategy` federates an end user's third-party OIDC JWT (Clerk, Supabase, Auth0, …) into a CTS service token. As of `@cipherstash/auth` `0.40` it takes a `workspaceCrn` (region derived from the CRN), matching `AccessKeyStrategy`. Pass it as `config.strategy` so every ZeroKMS request authenticates *as that user*, then bind the data key to a claim with `.withLockContext({ identityClaim })`:

```ts
import { Encryption, OidcFederationStrategy } from "@cipherstash/stack"

const client = await Encryption({
  schemas: [users],
  config: {
    strategy: OidcFederationStrategy.create(workspaceCrn, () => getUserJwt()),
  },
})

await client
  .encrypt("alice@example.com", { column: users.email, table: users })
  .withLockContext({ identityClaim: ["sub"] })
```

This replaces the old ceremony (`new LockContext()` → `await lc.identify(jwt)` → `.withLockContext(lc)`), which relied on a per-operation CTS token that protect-ffi removed in `0.25`.

- **`.withLockContext()`** now accepts a plain `{ identityClaim }` object (as well as a `LockContext`) and no longer requires a CTS token or an `identify()` call — it carries the identity claim only.
- **`LockContext.identify()` / `getLockContext()`** are **deprecated** (kept for backwards compatibility); the strategy handles token acquisition.
- **Strategies are re-exported** from `@cipherstash/stack` (`OidcFederationStrategy`, `AccessKeyStrategy`, `AutoStrategy`, `DeviceSessionStrategy`) and from `@cipherstash/stack/wasm-inline` (`OidcFederationStrategy`, `AccessKeyStrategy`) so integrators don't need a separate `@cipherstash/auth` install. `AuthStrategy` remains re-exported for the structural type.

Existing credential / env behaviour is preserved when `config.strategy` is omitted.
