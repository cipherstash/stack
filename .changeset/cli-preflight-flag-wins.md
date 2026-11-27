---
"stash": patch
---

`stash eql preflight --database-url <url>` now probes the database you name,
even when a `stash.config.ts` in the current folder or a folder above it sets a
literal `databaseUrl`. Before, preflight probed the config's database instead
and printed only a warning, so you could read the capabilities of the wrong
database. Preflight now matches `stash eql verify` and `stash eql install`,
where an explicit `--database-url` already wins. With no flag, nothing changes:
preflight uses the config's `databaseUrl` if it finds a `stash.config.ts`, and
otherwise the usual `DATABASE_URL` chain.
