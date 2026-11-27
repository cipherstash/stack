---
"stash": patch
---

`stash eql install --help` and `stash eql repair --help` now say that
`--database-url` wins over a literal `databaseUrl` in `stash.config.ts`. That is
what both commands already do: `eql install --database-url` never loads the
config, and `eql repair` never reads it.

Before, both showed the help text the other database commands share. That text
says the config literal wins. The commands still behave as before. Only the
help changed.

`stash eql verify --help` no longer prints "Also settable via DATABASE_URL"
twice. The `eql install` and `eql verify` help now also says that
`DATABASE_URL` on its own does not skip the config the way the flag does.
