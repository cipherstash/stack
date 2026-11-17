---
"stash": patch
---

The `stash-supabase` skill now says that tables with no encrypted columns are
read and written through the same `es.from()`, and that an embedded relation to
an encrypted table is refused rather than decrypted.
