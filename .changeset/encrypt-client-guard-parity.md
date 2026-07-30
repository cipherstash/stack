---
'stash': patch
---

`stash encrypt backfill` now names the cause when the encryption client has no
initialized encrypt config, instead of reporting a missing table.

The guard that refuses an unusable client file existed twice — once in
`loadEncryptConfig` (`stash db validate`) and once, hand-copied, in
`loadEncryptionContext` (`stash encrypt backfill`). The copies had already
drifted: for a client whose `getEncryptConfig()` returns nothing, `db validate`
exited 1 with `Encryption client in <file> has no initialized encrypt config`,
while `encrypt backfill` fell through to `Table "users" was not found in the
encryption client exports. Available: (none)` — naming the symptom rather than
the cause, which is precisely the failure the guard was added to eliminate.

Both loaders now call one shared guard, so a single file cannot produce two
different diagnoses, and the refusals are pinned at both public entry points.
The un-replaced `stash init` scaffold is unaffected — it was already refused by
both, with the same message.
