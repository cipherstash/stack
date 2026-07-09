---
"@cipherstash/stack": patch
"stash": patch
---

Refresh the bundled `stash-encryption` skill and fix the identity-aware
encryption docs it was copied from.

The skill ships inside the `stash` tarball and `stash init` installs it for
**every** integration (Drizzle, Supabase, plain PostgreSQL), so its errors reach
every user. It was last substantively updated before the auth-strategy rename.

- **Identity-aware encryption rewritten.** The chapter taught
  `new LockContext()` + `await lc.identify(userJwt)` + `CS_CTS_ENDPOINT`.
  Per-operation CTS tokens were removed in `protect-ffi` 0.25; the current path
  is `OidcFederationStrategy` on `config.authStrategy` plus
  `.withLockContext({ identityClaim })`.
- **`OidcFederationStrategy.create()` / `AccessKeyStrategy.create()` return a
  `Result` and must be unwrapped.** The envelope has no `getToken()`, so passing
  it straight to `authStrategy` fails inside the FFI. The JSDoc examples on
  `Encryption()` and the live `lock-context` test both did exactly that. Fixed
  in both, and documented in the skill and `AGENTS.md`.
- **The `lock-context` live tests passed without running.** They early-returned
  when `USER_JWT` was absent, reporting four green assertions that never
  executed — which is how the unwrap bug survived. They now `skipIf` out, so an
  absent credential reads as *skipped*, not *passed*.
- **Two copy-pasteable SQL bugs.** `CREATE EXTENSION IF NOT EXISTS eql_v2` — no
  such extension exists; `eql_v2` is a schema installed by `stash eql install`.
  And the fallback DDL declared `email jsonb NOT NULL`, which the shipped agent
  doctrine explicitly forbids because it breaks inserts during a rollout.
- **Post-cutover reads are not automatic.** The skill claimed `<col>` decrypts
  "transparently" after `stash encrypt cutover`, then contradicted itself one
  table row later. That is Proxy-only; SDK users must wire reads through the
  encryption client.
- Repoints the closed issue #447 at open #585; documents `stash db activate`
  (the additive push is promoted by `db activate`, not by cutover); scopes
  `db push` / `db activate` as EQL v2 + Proxy only; adds the missing
  `timestamp` data type and the SDK→EQL `cast_as` map; documents `authStrategy`
  and `eqlVersion` config, the `wasm-inline` / `v3` subpath exports, and the two
  distinct failure shapes (`EncryptionError.message` vs
  `AuthFailure.error.message`).
