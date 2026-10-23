---
'stash': patch
---

`stash encrypt backfill` now rejects a `--chunk-size` that is not a positive whole number (`abc`, `0`, `-5`, `1.5`) with a clear error and exit code 1, before loading the encryption client or opening a database connection. Previously the value reached the backfill engine unchecked: a non-numeric value became `NaN` and failed inside Postgres after the dual-write gate had already been recorded, under the generic "Backfill failed" message, and `0` reported a completed backfill having encrypted nothing. The default is unchanged at 1000 and is now shown in `--help`.
