---
name: stash-dynamodb
description: Integrate CipherStash encryption with Amazon DynamoDB using @cipherstash/stack/dynamodb and EQL v3 schemas. Covers item and bulk encryption, legacy v2 reads, HMAC query attributes, nested objects, audit logging, and the __source/__hmac storage convention.
---

# CipherStash Stack - DynamoDB Integration

Guide for integrating CipherStash field-level encryption with Amazon DynamoDB using `@cipherstash/stack/dynamodb`. The helper encrypts items before writing to DynamoDB and decrypts them after reading - it does not wrap the AWS SDK, so you keep full control of your DynamoDB operations.

## When to Use This Skill

- Adding field-level encryption to DynamoDB items
- Encrypting sensitive attributes before PutItem/BatchWrite
- Decrypting attributes after GetItem/BatchGet/Query/Scan
- Querying DynamoDB using encrypted partition or sort keys
- Building applications where PII or sensitive data is stored in DynamoDB
- Implementing audit logging for DynamoDB encryption operations

## Installation

```bash
npm install @cipherstash/stack @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb
```

> **Version note:** `npx stash init` is the preferred install path — it pins
> every `@cipherstash/*` package to the versions matching your CLI release.
> If you install manually as above, verify what actually resolved
> (`node -p "require('@cipherstash/stack/package.json').version"`): bare
> dist-tag installs can lag behind a release, and `stash init` will warn on
> the version skew.

## How It Works

CipherStash encrypts each attribute into two DynamoDB attributes:

| Original Attribute | Stored As | Purpose |
|---|---|---|
| `email` | `email__source` | Encrypted ciphertext |
| `email` | `email__hmac` | HMAC — written whenever the domain produces an equality term, usable only for equality lookups (see the domain table below) |

Non-encrypted attributes pass through unchanged. On decryption, the `__source` and `__hmac` attributes are recombined back into the original attribute name with the plaintext value.

**Only equality is usable on DynamoDB.** Ordering terms and free-text bloom filters have no DynamoDB query surface, so they are not stored. A column in an ordering or free-text domain still encrypts and decrypts correctly — it just cannot back a key condition.

## Schema and Stored Versions

Schema authoring and every write are EQL v3-only. Existing v2 DynamoDB items
remain readable by passing the same v3 table descriptor plus
`{ storedEqlVersion: 2 }` to `decryptModel` or `bulkDecryptModels`. Both entries
serve legacy reads — the default `@cipherstash/stack` one and
`@cipherstash/stack/wasm-inline`.

There is no infrastructure migration between the versions — DynamoDB has no EQL extension to install and no schema to alter — and there is no automatic *data* migration either. To fully move a table to v3, re-encrypt every item with the v3 schema.

The client must be built for the table. Build the client with the same v3 table you hand to `encryptedDynamoDB` — `Encryption({ schemas: [users] })` returns the typed v3 client for a concrete v3 schema set. Passing a v3 table to a client that never registered it (a client built for a different schema set) throws a clear error naming the table on the first operation, instead of failing later with an opaque FFI deserialization error.

DynamoDB items are natively nested. Declare encrypted leaves as flat dotted
paths; the item keeps its nested shape and unlisted siblings stay plaintext:

```typescript
const users = encryptedTable("users", {
  "profile.ssn": types.TextEq("profile.ssn"),
  "profile.note": types.Text("profile.note"),
})
```

```jsonc
{ "pk": "u#1",
  "profile": {
    "ssn__source": "<ciphertext>",
    "ssn__hmac": "<hmac>",        // equality term — FilterExpression only, not a key condition
    "note__source": "<ciphertext>",
    "city": "Sydney"              // not in schema, stays plaintext
  } }
```

> A nested equality term like `profile.ssn__hmac` lives *inside* the `profile`
> map, so it can only be matched with a `FilterExpression` — DynamoDB key
> conditions and secondary-index keys must be top-level scalar attributes. If you
> need the HMAC to back a key condition or GSI, declare the field as a top-level
> column (`ssn: types.TextEq("ssn")`) so it is stored as a top-level `ssn__hmac`.

> The dotted string is the *property key* as well as the column name — the model
> is matched by dotted path, so `{ profile: { ssn } }` resolves correctly.

To encrypt a whole subtree as one value instead of per-leaf, use `types.Json`, which stores it as a single ste_vec attribute (`profile__source`).

> **Arrays are not descended into.** The adapter splits encrypted leaves inside
> nested *objects* only. A value inside an array is stored whole — it is not
> split into `__source`/`__hmac`, so its ciphertext still decrypts on read but
> can never back a key condition, and it does not appear in the `__source`/`__hmac`
> attribute layout above. A DynamoDB key condition cannot target an array element
> in any case. To encrypt list data, either promote the searched field to a
> top-level column, or wrap the subtree in a single `types.Json` column.

## Rolling Encryption Out to Production

DynamoDB encryption is **single-deploy**. There is no rollout/cutover split — unlike the Postgres path, DynamoDB has no row-level rename swap and no shared-state proxy. The application owns every write, so adding encryption is an application-side change that ships in one PR:

1. Declare the encrypted schema (see Setup below).
2. Build an `encryptedDynamoDB` helper and call `encryptModel` / `decryptModel` at your write and read sites.
3. Ship the change.

For tables with **existing populated items**, the `__source` and `__hmac` attributes are added by the next write that touches each item. If you need every existing item encrypted at once (e.g. because a query uses `email__hmac` and would miss legacy items), run a one-shot script that reads every item, calls `encryptModel`, and writes it back. Idempotent: re-running an already-encrypted item is a no-op as long as the schema hasn't changed.

> **Where am I?** Run `stash status` (or `bunx`/`pnpm dlx`/`yarn dlx` per your runner) for a project-wide view across both Postgres and DynamoDB integrations. DynamoDB columns surface in the quest log as already-complete since there is no staged lifecycle to track.

## Setup

### 1. Define Encrypted Schema (EQL v3)

Each `types.*` factory is a concrete domain with fixed query capabilities. There are no chainable index methods — the type *is* the capability.

```typescript
import { encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", {
  email: types.TextEq("email"),      // equality -> queryable via email__hmac
  name: types.Text("name"),          // storage only
  phone: types.Text("phone"),        // storage only
  age: types.IntegerOrd("age"),      // decryptable, NOT queryable on DynamoDB
  metadata: types.Json("metadata"),  // JSON document
})
```

Which domains give you a `__hmac` attribute you can query on:

| Domain family | `__hmac` written? | Notes |
|---|---|---|
| `types.TextEq`, `IntegerEq`, `BigintEq`, `DateEq`, `TimestampEq`, `NumericEq`, `RealEq`, `DoubleEq`, `SmallintEq` | Yes | The equality domains — use these for anything you query |
| `types.TextOrd`, `TextOrdOre`, `TextSearch` | Yes | Text equality is HMAC-based even on ordering/search domains |
| `types.IntegerOrd`, `DateOrd`, `TimestampOrd`, and the other non-text `*Ord`/`*OrdOre` | **No** | Equality resolves through an ordering term in Postgres, which DynamoDB cannot use |
| `types.Text`, `Integer`, `Boolean`, and the other bare domains | No | Storage only |
| `types.Json` | No | Index terms live inside the ste_vec array; not splittable into an attribute |

> **Rule of thumb:** if an attribute will appear in a `KeyConditionExpression`, declare it with an `*Eq` domain.

### 2. Initialize Clients

```typescript
import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb"
import { Encryption } from "@cipherstash/stack"
import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"

const dynamoClient = new DynamoDBClient({ region: "us-east-1" })
const docClient = DynamoDBDocumentClient.from(dynamoClient)

const encryptionClient = await Encryption({ schemas: [users] })
const dynamo = encryptedDynamoDB({ encryptionClient })
```

> **Audit metadata on decrypt works.** `decryptModel` / `bulkDecryptModels` are
> audit-chainable — `dynamo.decryptModel(item, table).audit({ metadata })` forwards
> the metadata to ZeroKMS, whether the client came from `Encryption` or the
> `Encryption` client.

### Reading Existing EQL v2 Items

Use the current v3 table descriptor and select the stored wire version on the
read. No v2 builder or v2-configured client is needed.

**Works on both entries.** Schema authoring is EQL v3-only everywhere, but the
read itself is not: the legacy path reconstructs the v2 envelope around the
current v3 table, and `decrypt` accepts either wire generation. So Deno, Bun,
Workers and Supabase Edge Functions can read legacy items through
`@cipherstash/stack/wasm-inline` too.

```typescript
const decrypted = await dynamo.decryptModel(
  storedV2Item,
  users,
  { storedEqlVersion: 2 },
)
```

### Optional: Logger and Error Handler

```typescript
const dynamo = encryptedDynamoDB({
  encryptionClient,
  options: {
    logger: {
      error: (message, error) => console.error(`[DynamoDB] ${message}`, error),
    },
    errorHandler: (error) => {
      // Send to monitoring, etc.
      console.error(`[${error.code}] ${error.message}`)
    },
  },
})
```

## Encrypt and Write

### Single Item

```typescript
import { PutCommand } from "@aws-sdk/lib-dynamodb"

const user = {
  pk: "user#1",
  email: "alice@example.com",  // will be encrypted
  name: "Alice Smith",         // will be encrypted
  role: "admin",               // not in schema, passes through
}

const result = await dynamo.encryptModel(user, users)

if (result.failure) {
  console.error("Encryption failed:", result.failure.message)
} else {
  await docClient.send(new PutCommand({
    TableName: "Users",
    Item: result.data,
    // result.data looks like:
    // {
    //   pk: "user#1",
    //   email__source: "<ciphertext>",
    //   email__hmac: "<hmac>",
    //   name__source: "<ciphertext>",
    //   role: "admin",
    // }
  }))
}
```

### Bulk Items

```typescript
import { BatchWriteCommand } from "@aws-sdk/lib-dynamodb"

const items = [
  { pk: "user#1", email: "alice@example.com", name: "Alice" },
  { pk: "user#2", email: "bob@example.com", name: "Bob" },
]

const result = await dynamo.bulkEncryptModels(items, users)

if (!result.failure) {
  await docClient.send(new BatchWriteCommand({
    RequestItems: {
      Users: result.data.map(item => ({
        PutRequest: { Item: item },
      })),
    },
  }))
}
```

## Read and Decrypt

### Single Item

```typescript
import { GetCommand } from "@aws-sdk/lib-dynamodb"

const getResult = await docClient.send(new GetCommand({
  TableName: "Users",
  Key: { pk: "user#1" },
}))

const result = await dynamo.decryptModel(getResult.Item, users)

if (!result.failure) {
  console.log(result.data)
  // { pk: "user#1", email: "alice@example.com", name: "Alice Smith", role: "admin" }
}
```

### Bulk Items

```typescript
import { BatchGetCommand } from "@aws-sdk/lib-dynamodb"

const batchResult = await docClient.send(new BatchGetCommand({
  RequestItems: {
    Users: {
      Keys: [{ pk: "user#1" }, { pk: "user#2" }],
    },
  },
}))

const result = await dynamo.bulkDecryptModels(
  batchResult.Responses?.Users ?? [],
  users,
)

if (!result.failure) {
  for (const user of result.data) {
    console.log(user.email) // plaintext
  }
}
```

## Querying with Encrypted Keys

DynamoDB queries use key conditions, so you need to encrypt the search value into its HMAC form. Use `encryptionClient.encryptQuery()` to get the HMAC, then use it in your key condition.

### Encrypted Partition Key

When an encrypted attribute is the partition key (e.g., `email__hmac`):

```typescript
import { QueryCommand } from "@aws-sdk/lib-dynamodb"

// 1. Encrypt the search value to get the HMAC.
//    On an EQL v3 equality domain this mints the bare term — `{ v, i, hm }`
//    with no ciphertext — so `hm` is used directly.
const queryResult = await encryptionClient.encryptQuery("alice@example.com", {
  table: users,
  column: users.email,
})

if (queryResult.failure) {
  throw new Error(`Query encryption failed: ${queryResult.failure.message}`)
}

const emailHmac = queryResult.data.hm

// 2. Use the HMAC in a DynamoDB query
const result = await docClient.send(new QueryCommand({
  TableName: "Users",
  KeyConditionExpression: "email__hmac = :email",
  ExpressionAttributeValues: {
    ":email": emailHmac,
  },
}))

// 3. Decrypt the results
const decrypted = await dynamo.bulkDecryptModels(result.Items ?? [], users)
```

### Encrypted Sort Key

When an encrypted attribute is the sort key:

```typescript
const result = await docClient.send(new GetCommand({
  TableName: "Users",
  Key: {
    pk: "org#1",              // partition key (plain)
    email__hmac: emailHmac,   // sort key (encrypted HMAC)
  },
}))

const decrypted = await dynamo.decryptModel(result.Item, users)
```

### Encrypted Attribute in GSI

When querying a Global Secondary Index where the GSI key is an encrypted HMAC:

```typescript
const result = await docClient.send(new QueryCommand({
  TableName: "Users",
  IndexName: "EmailIndex",
  KeyConditionExpression: "email__hmac = :email",
  ExpressionAttributeValues: {
    ":email": emailHmac,
  },
  Limit: 1,
}))

if (result.Items?.length) {
  const decrypted = await dynamo.decryptModel(result.Items[0], users)
}
```

## Audit Logging

All operations support `.audit()` chaining for audit metadata:

```typescript
const result = await dynamo
  .encryptModel(user, users)
  .audit({
    metadata: {
      sub: "user-id-123",
      action: "user_registration",
      timestamp: new Date().toISOString(),
    },
  })
```

## DynamoDB Table Design Considerations

### Attribute Naming

For each encrypted field with an equality index, two attributes are stored:

- `{field}__source` - The encrypted ciphertext (binary/string)
- `{field}__hmac` - Deterministic HMAC for equality lookups

Fields without equality capability only get `__source` (no HMAC, so they can't be queried) — that means EQL v2 columns without `.equality()`, and EQL v3 columns outside the domains listed in the table above.

### Key Schema Design

| Pattern | Partition Key | Sort Key | Use Case |
|---|---|---|---|
| Plain PK | `pk` (plain) | - | Standard lookup by ID |
| Encrypted PK | `email__hmac` | - | Lookup by encrypted attribute |
| Encrypted SK | `pk` (plain) | `email__hmac` | Composite key with encrypted sort |
| GSI on HMAC | `pk` (plain) | - | Query by encrypted attribute via GSI with `email__hmac` as GSI PK |

### What You CAN Query

- Equality on `__hmac` attributes (exact match only)
- `attribute_exists(email__source)` / `attribute_not_exists(email__source)` in condition expressions

### What You CANNOT Query

- Range/comparison on encrypted attributes (no `BETWEEN`, `<`, `>` on `__source`)
- Substring matching on encrypted attributes (no `begins_with`, `contains` on `__source`)
- `__source` values are encrypted binary - only equality via `__hmac` is supported

## Error Handling

All operations return `Result<T, EncryptedDynamoDBError>` with either `data` or `failure`:

```typescript
const result = await dynamo.encryptModel(user, users)

if (result.failure) {
  console.error(result.failure.message)
  console.error(result.failure.code)
  // code: ProtectErrorCode | "DYNAMODB_ENCRYPTION_ERROR"
  console.error(result.failure.details)
}
```

## Complete API Reference

### `encryptedDynamoDB(config)`

```typescript
import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"

const dynamo = encryptedDynamoDB({
  // From Encryption(...)
  encryptionClient,
  options: {         // optional
    logger: { error: (message, error) => void },
    errorHandler: (error) => void,
  }
})
```

### Instance Methods

All methods accept an EQL v3 table. Decrypt defaults to stored EQL v3 and can
reconstruct a legacy v2 envelope when explicitly requested.

**EQL v3** — the item is checked against the table's column domains, and the result is typed as the attribute map that is actually stored: a declared column `email` becomes `email__source` (plus `email__hmac` if its domain mints one), NOT `email`.

| Method | Signature | Resolves to |
|---|---|---|
| `encryptModel` | `(item, v3Table)` | `EncryptedAttributes<Table, T>` |
| `bulkEncryptModels` | `(items, v3Table)` | `EncryptedAttributes<Table, T>[]` |
| `decryptModel` | `(storedItem, v3Table, readOptions?)` | `DecryptedAttributes<Table, T>` — `__source` folded back to the column, `__hmac` dropped |
| `bulkDecryptModels` | `(storedItems, v3Table, readOptions?)` | `DecryptedAttributes<Table, T>[]` |

Let `T` be inferred from the argument; do not pass explicit type arguments on the v3 path.

For a stored v2 item, pass `{ storedEqlVersion: 2 }` as `readOptions`. The table
is still the current v3 descriptor, which supplies table and column identity.

That descriptor must be one of the tables you passed to `Encryption({ schemas })`.
The adapter forwards it to the client to drive envelope and `Date` reconstruction,
and the client rejects a table it was not initialized with — so a legacy read of a
table your current schema no longer declares fails with `decryptModel received a
table this client was not initialized with`. Keep the table declared for as long
as you still need to read its v2 rows.

| Method | Signature | Resolves to |
|---|---|---|
| `decryptModel` | `(item, v3Table, { storedEqlVersion: 2 })` | `T` |
| `bulkDecryptModels` | `(items, v3Table, { storedEqlVersion: 2 })` | `T[]` |

**Grouped v2 fields.** A v2 column inside a group was stored as
`<group>.<leaf>__source` while the v2 schema knew it only as `<leaf>`. On a
`{ storedEqlVersion: 2 }` read the leaf is matched inside the group, so carrying
the column forward as a plain top-level `amount: types.TextEq('amount')` reads
those rows correctly. You can also name it by its full path, keeping the
original DB name — `'details.amount': types.TextEq('amount')`. Note the two
differ: the property is the dotted path, the argument is the v2 DB name. This
applies to v2 storage only; a v3 nested field uses the same dotted path for
both (`'profile.ssn': types.TextEq('profile.ssn')`).

All operations are thenable (awaitable) and support `.audit({ metadata })` chaining. On the default `@cipherstash/stack` entry the metadata forwards to ZeroKMS on every operation, encrypt and decrypt alike (see the Setup note). The `@cipherstash/stack/wasm-inline` client has no `.audit()` — its operations return a plain promise — so audit metadata is **dropped** there (logged at debug level). The operation itself still succeeds; only the audit record is lost. Use the native entry when audit trails matter.

Types exported from `@cipherstash/stack/dynamodb`: `EncryptedDynamoDBInstance`, `EncryptedDynamoDBConfig`, `EncryptedDynamoDBError`, `AnyEncryptedTable`, `DynamoDBReadOptions`, `DynamoDBEncryptionClient`, `EncryptedAttributes`, `DecryptedAttributes`, `AuditConfig`.

### Querying Encrypted Attributes

Use the encryption client directly (not the DynamoDB helper):

```typescript
// EQL v3 — the domain fixes the query type, so no `queryType` is needed:
const result = await encryptionClient.encryptQuery(
  "search-value",
  { table: users, column: users.email }
)
// encryptQuery returns a Result; check the failure branch before reading `data`.
// `data?.hm` would mask a failure (and a null-plaintext result) as `undefined`,
// producing a malformed key condition rather than a clear error.
if (result.failure) throw new Error(result.failure.message)
const hmac = result.data.hm  // Use this in DynamoDB key conditions

// EQL v2 — pass queryType explicitly (`usersV2` is the legacy table declared
// in the v2 read section above; `users` is the v3 one and infers its queryType):
const v2Result = await encryptionClient.encryptQuery(
  "search-value",
  { table: usersV2, column: usersV2.email, queryType: "equality" }
)
if (v2Result.failure) throw new Error(v2Result.failure.message)
const v2Hmac = v2Result.data.hm
```

> On a `types.TextSearch` column `encryptQuery` returns `hm` alongside ordering
> and bloom-filter terms regardless of `queryType`. Only `hm` is meaningful for
> DynamoDB — a free-text query cannot be expressed as a key condition.

## Complete Example

```typescript
import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand } from "@aws-sdk/lib-dynamodb"
import { Encryption } from "@cipherstash/stack"
import { encryptedTable, types } from "@cipherstash/stack/v3"
import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"

// Schema
const users = encryptedTable("users", {
  email: types.TextEq("email"),
  name: types.Text("name"),
})

// Clients
const dynamoClient = new DynamoDBClient({ region: "us-east-1" })
const docClient = DynamoDBDocumentClient.from(dynamoClient)
const encryptionClient = await Encryption({ schemas: [users] })
const dynamo = encryptedDynamoDB({ encryptionClient })

// Write
const user = { pk: "user#1", email: "alice@example.com", name: "Alice" }
const encResult = await dynamo.encryptModel(user, users)
if (!encResult.failure) {
  await docClient.send(new PutCommand({ TableName: "Users", Item: encResult.data }))
}

// Read by primary key
const getResult = await docClient.send(new GetCommand({
  TableName: "Users",
  Key: { pk: "user#1" },
}))
const decResult = await dynamo.decryptModel(getResult.Item, users)
if (!decResult.failure) {
  console.log(decResult.data.email) // "alice@example.com"
}

// Query by encrypted email (via HMAC)
const queryEnc = await encryptionClient.encryptQuery("alice@example.com", {
  table: users,
  column: users.email,
})
if (queryEnc.failure) throw new Error(queryEnc.failure.message)
const hmac = queryEnc.data.hm

const queryResult = await docClient.send(new QueryCommand({
  TableName: "Users",
  IndexName: "EmailIndex",
  KeyConditionExpression: "email__hmac = :e",
  ExpressionAttributeValues: { ":e": hmac },
}))

const decrypted = await dynamo.bulkDecryptModels(queryResult.Items ?? [], users)
```
