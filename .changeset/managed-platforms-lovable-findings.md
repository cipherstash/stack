---
'stash': patch
---

`stash-managed-platforms` skill: fold in what a live Lovable Cloud integration actually hit.

Four additions, each from a verified failure in the 2026-08-19 skilltester run
(cipherstash/skilltester branch `20260819-01-lovable`):

- **Command-time ceilings.** Replaying the ~2.6 MB EQL bundle with `psql -f` sends one statement
  per round trip and dies partway under Lovable's 600 s ceiling, leaving a half-installed schema.
  The skill now says to prefer `stash eql install` / the generated migration, gives the
  chunk-and-apply recipe for when raw SQL is unavoidable, and covers the ownership trap when
  cleaning up a half-install.
- **Data API grants.** The EQL install grants nothing to `authenticated` / `anon` /
  `service_role`, so every PostgREST function-form call fails until an explicit
  `GRANT USAGE / EXECUTE` — now stated with the exact SQL.
- **Install cooldowns.** Lovable's `bunfig.toml` `minimumReleaseAge` and Deno's
  `--minimum-dependency-age` both refuse a same-day CipherStash release; the skill names the
  exclude-list workaround and says to disclose it.
- **Lovable secrets.** There is no API (and no Lovable MCP tool) for setting project secrets; the
  order-of-operations step now says to mint with `stash env` and hand the values to the human for
  Project Settings → Secrets, without printing them.
