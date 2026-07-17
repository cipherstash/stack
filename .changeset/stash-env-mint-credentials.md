---
'stash': minor
---

`stash env` now works: it mints deployment credentials from your device-code
session and prints them as env vars — no dashboard copy-paste. The command
creates a fresh ZeroKMS client and a member-role CipherStash access key (named
via `--name`), then emits `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY`,
and `CS_CLIENT_ACCESS_KEY` to stdout, `--write` (`.env.production.local`, mode
0600), or `--json`. Creating access keys requires the admin role in the
workspace; the minted key itself is always member — the CLI deliberately
cannot mint admin keys.

This is also the supported credential path for WASM/edge local development
(Supabase Edge Functions, Cloudflare Workers, Deno), where the runtime cannot
read the `~/.cipherstash` device profile: mint a key and feed it via
`--env-file` or the platform's secret store.

The `STASH_EXPERIMENTAL_ENV_CMD` gate is removed.
