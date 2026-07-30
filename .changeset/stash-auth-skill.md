---
'stash': minor
'@cipherstash/wizard': patch
---

Add a `stash-auth` agent skill and install it for every integration (#794).

Authentication had no canonical home: the guidance was scattered across
skills that each mention one slice of it, and the gap had already produced a
wrong explanation in shipped material (conflating `config.authStrategy` with
lock context). The new skill is the single source of truth; other skills
should point at it rather than restate it.

What it documents:

- The service-token model: every request to a CipherStash service carries a
  short-lived JWT minted by CTS; access keys and IdP JWTs are exchanged at
  CTS, never sent to ZeroKMS directly. The token carries the workspace, the
  role-derived scopes, and the regional ZeroKMS endpoint in its `services`
  claim — which is why endpoints are never hand-configured and `CS_*_HOST`
  stays debug-only.
- The three separable concerns (client credentials, end-user identity,
  key binding) and the canonical statement that an auth strategy decides who
  the client is while a lock context decides who can retrieve a value's data
  key — the claim from the encrypting caller's service token is bound to the
  key, and retrieval requires presenting the same claim. Orthogonal, and
  only combined deliberately.
- The `@cipherstash/auth` strategies (`AutoStrategy`, `AccessKeyStrategy`,
  `OidcFederationStrategy`, `DeviceSessionStrategy`), including the Result
  trap: `create()` returns `Result<Strategy, AuthFailure>` and
  `config.authStrategy` takes the unwrapped `.data`, plus the `AuthFailure`
  codes worth recognising (`NOT_AUTHENTICATED`, `WORKSPACE_MISMATCH`, …).
- Credential discovery vs explicit config (native env/profile vs the WASM
  entry's explicit four values), the mutual-exclusion rule on the WASM entry,
  the four `CS_*` variables and `stash env`, and client lifetime with
  user-scoped strategies (one client per request — a shared client binds
  whoever arrived first).
- Lock context usage and the deprecations around it
  (`LockContext.identify()` / `getLockContext()`, `config.strategy`), the
  explicit rule that agents never read `~/.cipherstash`, and a note that
  Proxy authentication is a different path (dedicated skill to come).

`stash-zerokms` gains a companion section: ZeroKMS accepts only CTS-minted
service tokens, runs in multiple regions, and its endpoint is determined by
CTS — with the bulk deferred to `stash-auth`.
