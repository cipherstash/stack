---
'stash': minor
---

Add `stash eql migration` — generate an EQL **v3** install migration for your ORM
instead of running the SQL directly against the database (`stash eql install`).
Migration-first is the preferred path: the install lands in your migration history
and ships to every environment through the ORM's own migrate step.

```bash
stash eql migration --drizzle              # Drizzle custom migration
stash eql migration --drizzle --supabase   # also grants eql_v3 to anon/authenticated/service_role
```

The migration carries the CLI's bundled v3 install SQL (one source of truth) plus
the `cs_migrations` tracking schema, so a single `drizzle-kit migrate` covers
everything `stash encrypt …` needs. `--supabase` appends the `eql_v3` +
`eql_v3_internal` role grants for PostgREST/RLS access.

`--prisma` is registered but not available yet — it ships with prisma-next EQL v3
support and fails with a pointer until then.
