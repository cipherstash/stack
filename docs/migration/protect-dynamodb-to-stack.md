# Upgrade from Protect.js to Stack on DynamoDB

This guide moves an app from `@cipherstash/protect@10.2.1` and `@cipherstash/protect-dynamodb@6.0.1` to `@cipherstash/stack` 1.x. These versions also pull in `@cipherstash/protect-ffi@0.18.1` and `@cipherstash/schema@2.0.2`; the legacy versions are removed with Protect. Stack still depends on its own newer `@cipherstash/protect-ffi`.

For the tested top-level text, numeric and boolean attributes, existing ciphertext can stay **untouched**. Stack decrypts it as stored; text and numeric equality terms remain compatible when the schema and normalization rules below are followed. Boolean lookups need an application change, and legacy `dataType('json')` attributes need a separate conversion before the standard Stack adapter can read them. The no-backfill path does not cover those JSON attributes. Go straight to Stack 1.x; an intermediate hop through `@cipherstash/stack` 0.19 adds nothing (`compat › Stack 0.19 re-writes the same attributes and the same __hmac values Protect wrote`).

Compatibility claims below cite their supporting tests, prefixed with the suite it lives in (compat › *test name*):

- `compat` is `e2e/tests/protect-dynamodb-compat.e2e.test.ts`.
- `crossover` is `e2e/tests/protect-crossover.e2e.test.ts`.

Both suites produce item objects with the real Protect.js versions above, installed from npm, and read them back with the in-tree Stack package (currently 1.2.1). They test live encryption, but do not contact DynamoDB: item persistence and HMAC matching are simulated in memory. The crossover suite also runs real Postgres inserts and SQL queries. This verifies adapter compatibility, not AWS expressions, GSI configuration or a deployed customer application. They run on every pull request in the `e2e-tests` job of `.github/workflows/tests.yml`. Both need `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY` and `CS_CLIENT_ACCESS_KEY`, supplied in the environment, `e2e/.env` or the repository-root `.env`. The crossover suite also needs `DATABASE_URL` for a disposable Postgres database where it can install EQL and create tables. From an installed repository checkout, build the native binding and run through Turbo so workspace dependencies are built:

```bash
pnpm --filter @cipherstash/protect-ffi run build:native
pnpm exec turbo run test:protect-compat --filter @cipherstash/e2e --env-mode=loose
pnpm exec turbo run test:protect-crossover --filter @cipherstash/e2e --env-mode=loose
```

The native build needs the repository's Rust toolchain and trusted mise configuration. These commands are for maintainers verifying the guide; a customer installing Stack from npm receives prebuilt binaries.

## Why the supported scalar attributes need no re-encryption

protect-dynamodb stores each encrypted attribute as at most two strings, with no EQL version on disk (`compat › stores only __source and __hmac — no EQL version on disk`):

- `<attr>__source` is the ciphertext.
- `<attr>__hmac` is the equality term, present only on columns with an equality index.

Stack reads and writes the same two attributes:

- It decrypts a legacy `__source` with no read option (`compat › every legacy item decrypts, one at a time, with no read option`, `compat › every legacy item decrypts in one bulk call`), and gets the same plaintext protect-dynamodb does (`compat › agrees with what protect-dynamodb itself decrypts`).
- Its `encryptQuery` mints the same `__hmac` that protect-dynamodb's `createSearchTerms` did (`compat › matches protect-dynamodb createSearchTerms for the same value`), so the tested text and numeric equality queries match the expected legacy items (`compat › every equality query finds exactly the legacy rows it should`).
- A new Stack write sits beside legacy items, and one query and one bulk read cover both (`compat › new Stack writes sit beside legacy items: one query and one bulk read cover both`).
- Reading and querying leave the stored items byte-identical (`compat › Stack's reads and queries left every stored item byte-identical`).
- A tampered ciphertext fails to decrypt; it never returns wrong plaintext (`compat › fails, never returns wrong plaintext, when the ciphertext is tampered with`).

## Steps

### 1. Inventory the schema

List every `csTable` and `csColumn` the app declares, with its `dataType` and index (`equality()`, `equality([{ kind: 'downcase' }])`, or none). Find every `createSearchTerms` call, every `UpdateItem` that sets an encrypted attribute, and every query that filters on a boolean `__hmac`.

Done when every column has a row in the mapping table in step 3, and every column outside that table is listed as untested (see "Outside what the tests cover").

### 2. Swap the packages

```bash
pnpm remove @cipherstash/protect @cipherstash/protect-dynamodb
pnpm add '@cipherstash/stack@^1.2.1'
```

If the app's `package.json` also declares `@cipherstash/schema` or `@cipherstash/protect-ffi` directly, remove those in a separate `pnpm remove`. Do not add them to the command above when they are only transitive: `pnpm remove` refuses a package the manifest does not declare and then removes nothing.

Stack needs Node.js 22 or later. It reads the same four `CS_*` variables from the environment, so retain the same workspace and key access used to write the data. If the app passed credentials explicitly to Protect, populate these environment variables or configure the equivalent Stack credentials. If the app passed a `keyset` to `protect()`, pass the same keyset to `Encryption` as `config.keyset`. A client bound to a different keyset either fails to decrypt or, if it was granted the old keyset, decrypts but mints terms that match no existing `__hmac`. Keysets are untested by these suites.

Stack finds its service endpoints from `CS_WORKSPACE_CRN`. Protect 10.2.1 did not: outside `ap-southeast-2` it needed `CS_CTS_HOST` and `CS_ZEROKMS_HOST` set explicitly. Stack still honours both variables when they are set, so remove them from ordinary managed deployments. Keep them only for a deliberately configured private or custom endpoint, and check that endpoint before relying on it.

Done when `pnpm list --depth Infinity | grep cipherstash` shows `@cipherstash/stack` and its own dependencies (including its own newer `@cipherstash/protect-ffi`), and no `@cipherstash/protect@`, `@cipherstash/protect-dynamodb` or `@cipherstash/schema` line.

### 3. Translate the schema

Keep every **property key** exactly as it was. Stack finds `<key>__source` by property key, and a renamed key does not fail: the read returns the raw ciphertext under the old attribute name and leaves the new key unset (`compat › passes raw ciphertext through, with no failure, when a property key was renamed`). The table name and DB column names are free to change; neither is needed to decrypt or to mint the term (`compat › decrypts under a renamed table and renamed DB column names`, `compat › the HMAC is bound to neither table nor column`). Keeping them the same is simplest.

| Protect 10.2.1 column | Stack 1.x domain | Notes | Proved by |
|---|---|---|---|
| `csColumn(k).equality()` (text) | `types.TextEq(k)` | | `compat › %s: Stack %s encryptQuery reproduces the stored __hmac` |
| `csColumn(k).dataType('number').equality()` | `types.IntegerEq(k)` for whole numbers, `types.DoubleEq(k)` for fractions | Choose a domain that represents the data; whole-number and fractional compatibility are tested | `compat › IntegerEq and DoubleEq queries match the legacy whole-number HMAC`, `compat › DoubleEq preserves fractional number reads, writes and equality terms` |
| `csColumn(k).dataType('bigint').equality()` | `types.BigintEq(k)` | Reads return a JS `bigint`, not a `number`; the value is unchanged | `compat › changes the JS type of a bigint column, but not its value` |
| `csColumn(k).equality([{ kind: 'downcase' }])` | `types.TextEq(k)` | The app now lowercases: see step 5 | `compat › a v2 downcase filter is reproduced only by lowercasing first` |
| `csColumn(k).dataType('boolean').equality()` | `types.Boolean(k)` | Decrypts, but is no longer queryable: see step 5 | `compat › the one query a Stack 1.x app cannot mint is a boolean equality, with or without a rewrite` |
| `csColumn(k)` (text, no index) | `types.Text(k)` | Text only; unindexed number, bigint and boolean columns are untested | `compat › every legacy item decrypts, one at a time, with no read option` |
| `csColumn(k).dataType('json')` | `types.Json(k)`, after a one-off backfill | Requires conversion for the standard adapter: see step 5 | `compat › backfills to a types.Json item that Stack 1.x reads` |
| `csColumn(k).dataType('date')` | No verified mapping | The tested date inputs fail to encrypt in Protect 10.2.1; investigate any existing date attributes separately | `compat › protect 10.2.1 rejects the tested date inputs` |

Give each supported text or numeric equality column an `Eq` domain; boolean lookups need the separate treatment in step 5. An `Ord` domain such as `types.IntegerOrd` mints no equality term, so lookups on that column would find nothing (`compat › a numeric *Ord domain emits no HMAC at all`).

```typescript
// Before
import { csColumn, csTable } from '@cipherstash/protect'

const users = csTable('users', {
  email: csColumn('email').equality(),
  emailLower: csColumn('emailLower').equality([{ kind: 'downcase' }]),
  age: csColumn('age').dataType('number').equality(),
  balance: csColumn('balance').dataType('bigint').equality(),
  active: csColumn('active').dataType('boolean').equality(),
  notes: csColumn('notes'),
})

// After
import { encryptedTable, types } from '@cipherstash/stack/v3'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  emailLower: types.TextEq('emailLower'),
  age: types.IntegerEq('age'),
  balance: types.BigintEq('balance'),
  active: types.Boolean('active'),
  notes: types.Text('notes'),
})
```

Done when every column from step 1 has its Stack domain and every property key is unchanged.

### 4. Swap the client, the adapter and the search terms

Build the client with every table the adapter will touch.

```typescript
// Before
import { protect } from '@cipherstash/protect'
import { protectDynamoDB } from '@cipherstash/protect-dynamodb'

const protectClient = await protect({ schemas: [users] /* , credentials */ })
const dynamo = protectDynamoDB({ protectClient })

// After
import { encryptedDynamoDB } from '@cipherstash/stack/dynamodb'
import { Encryption } from '@cipherstash/stack/v3'

const client = await Encryption({ schemas: [users] })
const dynamo = encryptedDynamoDB({ encryptionClient: client })
```

`encryptModel(model, table)`, `bulkEncryptModels(models, table)`, `decryptModel(item, table)` and `bulkDecryptModels(items, table)` keep their names and arguments. Each returns `{ data }` or `{ failure }`, as before. A read needs no `{ storedEqlVersion: 2 }` option for these items, because a top-level attribute carries no version; one read call covers items written before and after the upgrade (`compat › reads the same item with no storedEqlVersion at all (scalars carry no version)`).

Replace each `createSearchTerms` call with `client.encryptQuery`, and use its `hm` as the `__hmac` value in the key condition or filter:

```typescript
// Before
const terms = await dynamo.createSearchTerms([
  { value: 'ada@example.com', column: users.email, table: users },
])
if (terms.failure) throw new Error(terms.failure.message)
const [emailHmac] = terms.data

// After
const term = await client.encryptQuery('ada@example.com', {
  table: users,
  column: users.email,
})
if (term.failure) throw new Error(term.failure.message)
const emailHmac = hmacOf(term.data)

// encryptQuery's result type also covers ciphertexts, strings and null, so
// narrow to the equality term before reading `hm`.
function hmacOf(term: unknown): string {
  if (typeof term === 'object' && term !== null && 'hm' in term && typeof term.hm === 'string') {
    return term.hm
  }
  throw new Error('encryptQuery returned no equality term: is the column an *Eq domain?')
}
```

Done when no file imports `@cipherstash/protect` or `@cipherstash/protect-dynamodb`, and the app type-checks.

### 5. Handle the known differences

These are the differences established by the tested schemas. Work through each one that step 1 found.

**Boolean lookups.** A `types.Boolean` column decrypts, but `encryptQuery` refuses it with `no indexes configured`, and a Stack write stores no `active__hmac` (`compat › a v3 Boolean writes no __hmac, though protect-dynamodb wrote one`). Re-encrypting does not bring the lookup back. If the app filters on a boolean, redesign that lookup before deploying. A plaintext attribute exposes the value, so use it only if that is acceptable for the field. A GSI requires a supported key representation, such as a string; a DynamoDB boolean cannot itself be a GSI key ([AWS key requirements](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html)). Populating a replacement attribute on existing items is a separate backfill, outside this suite.

**Bigint values.** Protect's tested bigint input is a safe JS `number`; Stack reads it as a JS `bigint`. Pass `bigint` values to `types.BigintEq` writes and queries (for example, `BigInt(balance)` after checking `Number.isSafeInteger(balance)`). Update JSON serialization and API boundaries accordingly. The suite does not establish lossless rollback for new values outside the safe-number range.

**In-place updates of a column with no term.** When an `UpdateItem` sets a `Boolean` (or any other domain that writes no `__hmac`) on a legacy item, `REMOVE` the old `<attr>__hmac` in the same update. With `SET` alone, the stale term still matches a lookup on the old value (`compat › a Stack Boolean update writes no __hmac, so a partial update must REMOVE the legacy one`).

```typescript
UpdateExpression: 'SET active__source = :active REMOVE active__hmac'
```

**`downcase` columns.** Stack has no `downcase` filter, so the app lowercases the value itself, on both sides:

- Lowercase the value before `encryptQuery`, and the term matches the stored `__hmac` (`compat › a v2 downcase filter is reproduced only by lowercasing first`).
- Lowercase the value before every write too. Stack hashes a mixed-case value as given, so a lowercase query would miss it (`compat › a Stack write keeps mixed-case plaintext only by giving up the legacy HMAC`).

Lowercasing on write means new items store the lowercased value, where protect-dynamodb kept the original casing in the ciphertext. If the app needs the original, store it in a second attribute, for example `emailDisplay: types.Text('emailDisplay')`, and keep the lowercased one for lookups.

**`dataType('json')` columns.** Protect stored a JSON value as a scalar ciphertext, which does not read as `types.Json` through the adapter (`compat › fails to read through encryptedDynamoDB with types.Json (known gap)`). The tested conversion uses a JSON object; `types.Json` accepts documents (objects, arrays or null), so scalar JSON values need a separate schema decision. Backfill each supported document once: rebuild the legacy envelope, decrypt it with `client.decrypt`, and write it back with a `types.Json` column (`compat › reads through client.decrypt() on a rebuilt v2 scalar envelope`, `compat › backfills to a types.Json item that Stack 1.x reads`).

```typescript
const docs = encryptedTable('docs', { profile: types.Json('profile') })
const jsonClient = await Encryption({ schemas: [docs] })
const jsonDynamo = encryptedDynamoDB({ encryptionClient: jsonClient })

if (typeof item.profile__source !== 'string') {
  throw new Error('Expected a legacy scalar JSON ciphertext')
}
const value = await jsonClient.decrypt({
  v: 2,
  k: 'ct',
  i: { t: 'docs', c: 'profile' }, // the Protect table and column names
  c: item.profile__source,
})
if (value.failure) throw new Error(value.failure.message)
// This example uses the profile shape exercised by the compatibility suite.
// Validate against your application's JSON schema before using its type.
const profile = value.data as { roles: string[]; tz: string }
const rewritten = await jsonDynamo.encryptModel({ profile }, docs)
if (rewritten.failure) throw new Error(rewritten.failure.message)
// Persist only the returned profile attributes with UpdateItem, preserving
// the item's keys and all other attributes. Guard against concurrent changes.
// This call encrypts in memory; it does not write anything to DynamoDB.
```

Before replacing JSON attributes, plan rollback separately: the original Protect JSON schema cannot read the new representation (`compat › the original Protect JSON schema cannot read a Stack Json rewrite`). The snippet is a conversion example, not a resumable backfill runner.

Done when each boolean lookup has an approved replacement, bigint callers use the correct JS type, each partial update of a term-less column removes its `__hmac`, each `downcase` column is lowercased on every write and query, and each JSON item is backfilled.

### 6. Verify against your own data

Before deploying, run the new code against a copy of real items:

- Decrypt a sample of legacy items with Stack and compare each to what the Protect build decrypts. Every field matches, with `bigint` columns now a JS `bigint`.
- For each supported text or numeric equality column, normalize downcase inputs and use bigint inputs where required, then mint a term with `encryptQuery` for a known value and confirm it equals the stored `<attr>__hmac` of an item holding that value.

Done when both checks pass for every table.

### 7. Deploy, with rollback available

Deploy after the application-specific checks pass. For the tested scalar values, rollback can redeploy the Protect build without rewriting ciphertext: protect-dynamodb 6.0.1 reads items Stack wrote (`compat › an item written by Stack 1.x reads back through protect-dynamodb 6.0.1`), and Stack writes the same `__hmac` protect-dynamodb wrote (`compat › Stack 1.x writes the same __hmac protect-dynamodb wrote`). The scalar cycle (legacy write, mixed update, optional scalar rewrite, HMAC matching, rollback) runs with in-memory persistence in `compat › runs the migration and keeps every generation readable and queryable`.

Rollback limitations: JSON converted to `types.Json` needs a separate reverse conversion or a reader that handles both formats; values outside the tested numeric range need independent verification; boolean items Stack wrote have no `__hmac`, so the Protect build cannot find them by boolean lookup; and lowercased `downcase` values stay lowercased.

## Optional: moving values between DynamoDB and Postgres

For the tested text equality, integer equality and storage-only text columns, a value moves between DynamoDB and a Postgres EQL v3 column as a **copy** of two strings, in either direction, with no key and no re-encryption:

| DynamoDB attribute | Postgres EQL v3 envelope field |
|---|---|
| `<attr>__source` | `c` (the ciphertext) |
| `<attr>__hmac` | `hm` (the equality term) |

The rest of the envelope is `{ v: 3, i: { t: <table>, c: <column> } }`, which carries no secret and comes from the schema. Use `eql_v3_text_eq` and `eql_v3_integer_eq` columns for equality columns, and `eql_v3_text` for storage-only text; install EQL v3 with `npx stash eql install`.

```typescript
const toEnvelope = (item, column) => ({
  v: 3,
  i: { t: 'users', c: column },
  c: item[`${column}__source`],
  ...(typeof item[`${column}__hmac`] === 'string' ? { hm: item[`${column}__hmac`] } : {}),
})

const toAttributes = (envelope, column) => ({
  [`${column}__source`]: envelope.c,
  ...(typeof envelope.hm === 'string' ? { [`${column}__hmac`]: envelope.hm } : {}),
})
```

What the crossover suite proves:

- protect-dynamodb items copied into Postgres are accepted by the column types (`crossover › the EQL v3 column domains accept the copied attributes`), arrive byte-for-byte (`crossover › stores the DynamoDB ciphertext and HMAC byte-for-byte`), decrypt with Stack (`crossover › Stack 1.x decrypts the Postgres rows`), and are found by SQL equality (`crossover › SQL equality queries find exactly the right rows`).
- Copying back returns the original item exactly (`crossover › round trip DynamoDB → Postgres → DynamoDB returns the original item exactly`).
- A Stack-written Postgres row copied into DynamoDB decrypts with Stack (`crossover › Stack 1.x encryptedDynamoDB decrypts the item`) and with protect-dynamodb 6.0.1 (`crossover › protect-dynamodb 6.0.1 decrypts the item too`), and carries the `__hmac` a native write would (`crossover › the item carries the same __hmac a native DynamoDB write would, so existing key conditions match it`).
- Raw payloads from Protect's `encrypt` copy into both stores the same way (`crossover › becomes a DynamoDB item Stack 1.x decrypts, identical to what protect-dynamodb wrote`, `crossover › becomes a Postgres EQL v3 row that SQL finds and Stack 1.x decrypts`).

## Outside what the tests cover

The suites cover the examples in the step 3 table, including expected failures for JSON reads and date encryption. Verify anything else against your own data with step 6 before relying on it, in particular:

- columns with `orderAndRange()`, `freeTextSearch()` or other index kinds;
- unindexed `number`, `bigint` or `boolean` columns (only unindexed text is tested);
- nested or grouped attributes;
- items written with a lock context;
- Unicode normalization beyond the ASCII `downcase` examples, numeric precision boundaries, and JSON rollback after conversion;
- real DynamoDB requests, pagination, GSI behavior, concurrent updates, or production backfill orchestration.
