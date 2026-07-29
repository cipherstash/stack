---
'stash': patch
---

`stash encrypt backfill` now distinguishes a missing encrypted column from a
legacy EQL v2 one. The domain probe returns the same "not v3" answer for both,
so a user who had simply not added the `<col>_encrypted` column yet was told
they were on a legacy EQL v2 column and advised to migrate a domain that did not
exist. The command now reports that the column is absent, points at adding an
`eql_v3_*`-domain column and applying the migration, and mentions
`--encrypted-column` for non-standard names. The EQL v2 message is unchanged for
columns that really are present.
