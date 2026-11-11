# Customer records

This application uses Protect.js to encrypt customer records in DynamoDB Local.
It copies the `email`, `age` and `notes` ciphertexts into Postgres EQL v3 columns
and can copy them back. Postgres is already EQL v3; upgrading an EQL v2 database
is outside this exercise.

Migrate the application using `migration-guide.md`. Edit `src/app.mjs`,
`src/stores.mjs` and the package manifest/lockfile. Keep the exported API below
so the harness can check the same behavior before and after the migration.
Record unclear instructions and failed approaches in `friction.md`.

`createApp(env)` needs the four `CS_*` credentials, `HARNESS_DYNAMO_URL`,
`HARNESS_TABLE`, and `DATABASE_URL`. The harness creates the databases and
supplies these values. Call `close()` when finished.

- `put(customer)`, `get(pk)`: encrypted DynamoDB write/read. Missing reads return `null`.
- `findEmail(value)`, `findEmailLower(value)`, `findAge(value)`,
  `findBalance(value)`, `findActive(value)`: return matching decrypted customers.
  Email is case sensitive; emailLower is case insensitive. Keep active encrypted;
  a paginated scan followed by decryption and filtering is acceptable for this small app.
- `setActive(pk, active)`: update only the active field of an existing customer.
- `copyToPostgres(pk)`, `copyToDynamo(pk)`: copy ciphertext without re-encryption.
  Copying back preserves the existing DynamoDB-only fields.
- `getPostgres(pk)`, `findPostgresEmail(value)`, `findPostgresAge(value)`:
  return decrypted records containing only `pk`, `email`, `age` and `notes`.

A customer has `pk`, `email`, `emailLower`, `age`, `balance`, `active`, and
`notes`. At this public API, `balance` is a decimal integer **string** for JSON
compatibility; the legacy encryption boundary converts it to a safe JS number.
The migration may lowercase new `emailLower` plaintext, as described by the
guide. Existing records must remain readable and queryable without rewriting
their ciphertext. JSON documents are a separate future scenario.

`npm run check` checks JavaScript syntax. It is not a database or encryption test;
use the harness acceptance command for those checks.
