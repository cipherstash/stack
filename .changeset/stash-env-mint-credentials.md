---
'stash': minor
---

`stash env` now works: it mints deployment credentials from your device-code
session and prints them as env vars — no dashboard copy-paste. The command
creates a fresh ZeroKMS client and a member-role CipherStash access key (named
via `--name`; the role is pinned in the request and verified on the response —
the CLI deliberately cannot mint admin keys), then emits `CS_WORKSPACE_CRN`,
`CS_CLIENT_ID`, `CS_CLIENT_KEY`, and `CS_CLIENT_ACCESS_KEY`.

Output goes to stdout by default — and stdout is pipe-clean (progress UI is on
stderr), so `stash env --name x > prod.env` and pipes into secret stores are
safe. `--write [path]` writes a file instead (default `.env.production.local`,
enforced mode 0600 even when overwriting), confirming before overwriting and
refusing non-interactively — always *before* anything is minted, so a refusal
never discards the shown-exactly-once access key. `--json` emits NDJSON; with
`--write` the confirmation event is deliberately secret-free. API responses
are schema-validated so a service change can never print `undefined` into a
credentials file. Creating access keys requires the admin role in the
workspace.

This is also the supported credential path for WASM/edge local development
(Supabase Edge Functions, Cloudflare Workers, Deno), where the runtime cannot
read the `~/.cipherstash` device profile: mint a key and feed it via
`supabase functions serve --env-file` or the platform's secret store.

The `STASH_EXPERIMENTAL_ENV_CMD` gate is removed.
