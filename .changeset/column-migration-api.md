---
'@cipherstash/migrate': minor
'stash': patch
---

`@cipherstash/migrate` adds `ColumnMigration`, one place for the rules of a column migration in either direction: which twin column it pairs with (the flag, the recorded pairing, the manifest, then the naming convention), its phase, whether a forced pass is owed, and which open migration in the other direction blocks it.
`ColumnMigration.load()` reads it from `cipherstash.cs_migrations`; `confirmDualWrites()`, `recordDropGenerated()` and `recordSourceRemoved()` record events, refusing those the rules forbid with a `ColumnMigrationError`.
The pure rules are exported as `deriveColumnMigration`, `openCounterpart`, `planPassFor`, `passProgress`, `deriveTwinName` and `manifestTwin`.

`runBackfill` and `runDecryptBackfill` now apply the rules themselves rather than leaving them to the caller.
Every event records whether its pass was forced.
An interrupted forced pass is finished as one by the next run, with or without `force`, and the result says why in `forcedBy`.
A forward backfill resumes after a failed run from its last committed position, counts its total once when it resumes a forced pass, and refuses to start while a reverse migration of the same columns is open.
`runBackfill` now throws a `ColumnMigrationError` with code `twin-mismatch` when `encryptedColumn` differs from the encrypted column already recorded for that column, rather than continuing into a different one.
A reverse backfill over a twin that already holds values is forced unless the caller confirmed dual-writes with the `plaintext-current` waiver.
Error events store the error's class (`errorName`) and safe details instead of its message, which could carry row data.

`stash decrypt plan`, `status`, `backfill` and `drop` resolve every column through `ColumnMigration`, so they always agree on the twin and the phase.
`decrypt status` flags `forward-open`, `twin-has-values` and `forced-pass-owed`.
`decrypt backfill --confirm-plaintext-current` is accepted on a later run as long as no forced pass has started, and refused while a started forced pass is owed.
