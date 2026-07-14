---
'stash': minor
---

`stash eql install --eql-version 3` now installs the eql-3.0.0 GA bundle,
vendored from the pinned `@cipherstash/eql` package (sha256-verified).

Since eql-3.0.0 one artifact installs everywhere: the operator-class
statements self-skip when the role lacks superuser (managed Postgres,
Supabase) and the bundle disables the ORE-backed encrypted domains it cannot
support. The separate v3 Supabase bundle variant is gone — `--supabase` and
`--exclude-operator-family` no longer select a different v3 file (the role
GRANTs for `eql_v3` / `eql_v3_internal` still apply with `--supabase`).

The bundled skills are also refreshed for the eql-3.0.0 naming convention
(`public.eql_v3_<name>` column domains) and the EQL v3 typed-schema surface.
