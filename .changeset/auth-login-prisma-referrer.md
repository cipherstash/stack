---
'stash': patch
---

`stash auth login` now accepts `--prisma`, bringing the integration referrer
flags to parity with `stash init`: `--supabase`, `--drizzle`, `--prisma`. A
multi-flag referrer is now ordered alphabetically, so it no longer depends on
argv order.

This closes a documentation/implementation gap: the bundled `stash-cli` skill
listed `--prisma` among `auth login`'s referrer flags, but the command did not
register it — and because the CLI's argument parser does not reject unknown
flags, `stash auth login --prisma` was silently dropped rather than erroring.
