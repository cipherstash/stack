---
"@cipherstash/stack": minor
---

Bump `@cipherstash/protect-ffi` to `0.25.0` and align the WASM-inline path with its API.

protect-ffi `0.25.0` is a breaking release for both entries:

- **WASM (`@cipherstash/stack/wasm-inline`)**: `newClient` now takes a single options object with the auth strategy nested under `strategy` (was a separate first argument). The WASM `Encryption()` config now takes a **`workspaceCrn`** instead of a `region` — the CRN is the single source of truth for workspace identity, and the `AccessKeyStrategy` region is derived from it (`crn:<region>:<workspace-id>`). `CS_REGION` is no longer consulted; set `CS_WORKSPACE_CRN`. This matches protect-ffi `0.25`, which dropped `CS_REGION` in favour of `CS_WORKSPACE_CRN`.
- **Node**: `serviceToken` was removed from the encrypt / decrypt / query option types (and the `CtsToken` export). The per-operation CTS token is no longer forwarded — auth flows through the client's strategy / credentials, while lock contexts continue to travel as `lockContext.identityClaim`. The public `LockContext` / `identify()` API is unchanged.

Also adds an optional **`config.strategy`** to `Encryption()` (Node): pass an `AuthStrategy` — any `{ getToken(): Promise<{ token }> }`-shaped object, e.g. `AccessKeyStrategy` from `@cipherstash/auth` — and its `getToken()` is invoked on every ZeroKMS request, taking precedence over the credentials-derived default (the `clientKey` is still used for encryption). Omitting it preserves the existing credentials / env behaviour. `AuthStrategy` is re-exported from `@cipherstash/stack`.
