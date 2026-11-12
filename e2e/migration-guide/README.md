# Protect v2 to Stack v3 examples

These examples accompany the [two-store migration guide](https://github.com/cipherstash/stack/blob/0ecabc3f62ee8a117c467981ce00d312e6cfc636/docs/migration/protect-dynamodb-to-stack.md). EQL v2/v3 are data generations; the target npm package is Stack 1.2.1. Nothing here uses v4.

Use Node.js 22.18 or later. Copy this directory to a disposable location outside the monorepo and run:

```bash
npm install
```

The exact direct package versions are in `package.json`; retain the generated npm lockfile for your rehearsal. In this checkout, the live tests import the same example functions against the in-tree Stack build instead. That is different evidence from a separately installed published tarball; record the tested version/revision when running either.

Set the original workspace credentials in a local `.env`:

```dotenv
CS_WORKSPACE_CRN=
CS_CLIENT_ID=
CS_CLIENT_KEY=
CS_CLIENT_ACCESS_KEY=
```

Do not commit credentials. The examples contain fixed, non-secret synthetic customer data. The legacy client temporarily sets managed service endpoints from the workspace region, then restores them; do not use this managed-host example unchanged with private/custom endpoints.

## DynamoDB

```bash
npm run dynamodb
```

This runs actual Protect/Stack encryption with **in-memory persistence**. Assertions cover preserved legacy bytes, reads, lowercase equality, fresh writes, bigint serialization and removal of the stale boolean term on partial updates. It makes no AWS requests and does not prove GSI, pagination or concurrent-update behavior. The broader compatibility suite covers the guide's JSON conversion and other exceptions.

## PostgreSQL

Provide `DATABASE_URL` for a **disposable** PostgreSQL database where EQL v2 and v3 are already installed. Existing customer databases already have v2; the integration suite installs the historical EQL 2.2.1 bundle only to create a realistic test starting point. Install v3 alongside it using `stash eql install`; never uninstall v2 as part of this example.

```bash
npm run postgres -- seed
npm run postgres -- migrate
npm run postgres -- verify
npm run postgres -- rollback
```

`seed` creates `protect_upgrade_example` with three Protect-written EQL v2 rows. It refuses to replace an existing table. `migrate` locks the table, refuses unsupported structure/data, creates v3 target columns and indexes, and verifies values before committing. `verify` reports counts without logging plaintext. `rollback` preserves the v2 sources and removes unchanged targets before application writes resume.

Then demonstrate fresh writes and the rollback boundary:

```bash
npm run postgres -- migrate
npm run postgres -- write
npm run postgres -- verify
npm run postgres -- rollback
```

The final command **must fail** because source columns do not contain the new Stack-only row. This is not a recovery service: after writes resume, reconcile changes or use a separately rehearsed recovery plan. Do not run `seed` again to conceal this condition.

The example deliberately supports only an uncustomized table with a text primary key, text equality, safe whole-number equality and storage-only text under the fixed `customers` logical identity. It refuses extra columns, secondary indexes, non-primary constraints, dependent views, user triggers, row-level security and inheritance. Review those objects rather than removing them to bypass a refusal.

Run the existing credentialed `test:protect-crossover` task from the repository to verify these functions against real Postgres and ZeroKMS. It also tests unsupported-input refusal, fresh writes and actual equality-index engagement. See the guide for the maintainer build commands.

`postgres-conversion.ts` is the self-contained conversion used by the example and reproduced verbatim in the guide. To update the checked-in snippet, run `node scripts/sync-migration-guide.mjs` from the repository root; `--check` verifies it without writing. Keep Protect installed in this separate migration tool until verification and the rollback decision are complete. The new application can remove Protect independently.
