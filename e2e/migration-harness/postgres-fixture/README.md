# PostgreSQL customer application

This application stores real Protect.js ciphertext in EQL v2 PostgreSQL columns.
Follow the supplied migration guide to upgrade it to Stack's v3 API. Preserve
the existing records and their source columns. The supported fields are text
equality (`email`), safe integer equality (`age`) and storage-only text (`notes`).

Keep the public API in `src/app.mjs`: `createApp(env)` returns `put(customer)`,
`get(pk)`, `findEmail(value)`, `findAge(value)` and `close()`. Customer values are
plain objects containing `pk`, `email`, `age` and `notes`. Missing records return
null; lookups return matching customers sorted by primary key. `src/stores.mjs`
exports `createStores(env)` with `init()` and `close()` methods.

The assigned database is disposable and contains the customer's original data.
Put the one-off database conversion in `src/migrate.mjs`, which exports
`async function migrate(env)`; it currently does nothing. It runs once against
the database, during a write-maintenance window, before the migrated
application starts. Running it a second time must be safe: it either succeeds
without changing data or refuses (throws) without changing anything. Keep the
source columns, populate separate v3 target columns and create the guide's
equality indexes. Do not reseed or delete existing data. `createApp` must not
alter the schema. New writes use the target columns after migration.

For checks outside the application API, use the harness acceptance command for those checks.
Record unclear instructions and failed approaches in `friction.md`.
