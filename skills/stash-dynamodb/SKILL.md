---
name: stash-dynamodb
description: Integrate CipherStash encryption with Amazon DynamoDB using @cipherstash/stack/dynamodb. Covers the encryptedDynamoDB helper for encrypting items before PutItem and decrypting after GetItem with EQL v3 (types.* domains) or EQL v2 schemas, bulk encrypt/decrypt for BatchWrite and BatchGet, querying with encrypted partition and sort keys via HMAC attributes, nested object encryption, audit logging, and the DynamoDB attribute naming conventions (__source/__hmac). Use when adding encryption to a DynamoDB project, encrypting items before writes, decrypting items after reads, or querying encrypted DynamoDB attributes.
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
| `email` | `email__hmac` | HMAC for equality lookups (only for equality-capable columns) |

Non-encrypted attributes pass through unchanged. On decryption, the `__source` and `__hmac` attributes are recombined back into the original attribute name with the plaintext value.

**Only equality is usable on DynamoDB.** Ordering terms and free-text bloom filters have no DynamoDB query surface, so they are not stored. A column in an ordering or free-text domain still encrypts and decrypts correctly — it just cannot back a key condition.

## Choosing a Schema Version

`encryptedDynamoDB` accepts both EQL v3 and EQL v2 tables. **Use EQL v3 for new projects.**

| | EQL v3 (recommended) | EQL v2 (existing deployments) |
|---|---|---|
| Import | `@cipherstash/stack/v3` | `@cipherstash/stack` + `@cipherstash/stack/schema` |
| Schema | `encryptedTable` + `types.*` | `encryptedTable` + `encryptedColumn` |
| Client | `EncryptionV3({ schemas })` | `Encryption({ schemas })` |
| Nested fields | **Not yet** (deferred) | `encryptedField` |

There is no data migration between them: DynamoDB has no EQL extension to install and no schema to alter. But the two write **different wire formats**, so a table populated under v2 cannot be read back with a v3 schema, or vice versa. Pick one per table and stay on it.

**Nested objects work differently in each version, and this is the main reason to stay on v2.**

EQL v2's `encryptedField` encrypts *selected leaves in place*. The item keeps its shape and unlisted siblings stay plaintext:

```jsonc
// schema: profile: { ssn: encryptedField("profile.ssn") }
{ "profile": { "ssn__source": "<ciphertext>", "city": "Sydney" } }
```

EQL v3 has no `encryptedField` authoring form — a nested group is a compile error, since a v3 column map holds only `types.*` domains.

The nearest v3 equivalent is `types.Json`, which encrypts the **whole subtree as a single value**:

```jsonc
// schema: profile: types.Json("profile")
{ "profile__source": [ /* ste_vec entries */ ] }
```

Choose accordingly:

| You want | Use |
|---|---|
| The whole object encrypted as one value | `types.Json` (v3) |
| Some leaves encrypted, siblings plaintext, structure preserved | `encryptedField` (v2 only) |

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
import { EncryptionV3 } from "@cipherstash/stack/v3"
import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"

const dynamoClient = new DynamoDBClient({ region: "us-east-1" })
const docClient = DynamoDBDocumentClient.from(dynamoClient)

const encryptionClient = await EncryptionV3({ schemas: [users] })
const dynamo = encryptedDynamoDB({ encryptionClient })
```

> **Audit metadata on decrypt:** the client from `EncryptionV3` has no audit
> surface on its decrypt methods, so `.audit()` on `decryptModel` /
> `bulkDecryptModels` resolves normally but the metadata is not recorded. If you
> need audited decrypts, build the client with `Encryption({ schemas: [users],
> config: { eqlVersion: 3 } })` instead — same v3 wire format, chainable decrypt.

### EQL v2 Schema (existing deployments)

```typescript
import { encryptedTable, encryptedColumn, encryptedField } from "@cipherstash/stack/schema"
import { Encryption } from "@cipherstash/stack"

const users = encryptedTable("users", {
  email: encryptedColumn("email").equality(),   // searchable via HMAC
  name: encryptedColumn("name"),                // encrypt-only, no search
  metadata: encryptedColumn("metadata").dataType("json"),
  profile: {                                     // nested objects: v2 only
    ssn: encryptedField("profile.ssn"),
  },
})

const encryptionClient = await Encryption({ schemas: [users] })
const dynamo = encryptedDynamoDB({ encryptionClient })
```

> **Note:** `encryptedColumn` also supports `.orderAndRange()`, `.freeTextSearch()`, and `.searchableJson()` index methods, but only `.equality()` produces HMAC values usable for DynamoDB key condition queries.

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
  // From EncryptionV3(...) or Encryption(...)
  encryptionClient,
  options: {         // optional
    logger: { error: (message, error) => void },
    errorHandler: (error) => void,
  }
})
```

### Instance Methods

`table` is either an EQL v3 table (`types.*` domains) or an EQL v2 one.

| Method | Signature | Returns |
|---|---|---|
| `encryptModel` | `(item: T, table)` | `EncryptModelOperation<T>` |
| `bulkEncryptModels` | `(items: T[], table)` | `BulkEncryptModelsOperation<T>` |
| `decryptModel` | `(item: Record<string, unknown>, table)` | `DecryptModelOperation<T>` (resolves to `Decrypted<T>`) |
| `bulkDecryptModels` | `(items: Record<string, unknown>[], table)` | `BulkDecryptModelsOperation<T>` (resolves to `Decrypted<T>[]`) |

All operations are thenable (awaitable) and support `.audit({ metadata })` chaining. See the note in Setup about decrypt-side audit metadata and the `EncryptionV3` client.

### Querying Encrypted Attributes

Use the encryption client directly (not the DynamoDB helper):

```typescript
// EQL v3 — the domain fixes the query type, so no `queryType` is needed:
const result = await encryptionClient.encryptQuery(
  "search-value",
  { table: users, column: users.email }
)
const hmac = result.data?.hm  // Use this in DynamoDB key conditions

// EQL v2 — pass queryType explicitly:
const v2Result = await encryptionClient.encryptQuery(
  "search-value",
  { table: users, column: users.email, queryType: "equality" }
)
const v2Hmac = v2Result.data?.hm
```

> On a `types.TextSearch` column `encryptQuery` returns `hm` alongside ordering
> and bloom-filter terms regardless of `queryType`. Only `hm` is meaningful for
> DynamoDB — a free-text query cannot be expressed as a key condition.

## Complete Example

```typescript
import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand } from "@aws-sdk/lib-dynamodb"
import { EncryptionV3, encryptedTable, types } from "@cipherstash/stack/v3"
import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"

// Schema
const users = encryptedTable("users", {
  email: types.TextEq("email"),
  name: types.Text("name"),
})

// Clients
const dynamoClient = new DynamoDBClient({ region: "us-east-1" })
const docClient = DynamoDBDocumentClient.from(dynamoClient)
const encryptionClient = await EncryptionV3({ schemas: [users] })
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
const hmac = queryEnc.data?.hm

const queryResult = await docClient.send(new QueryCommand({
  TableName: "Users",
  IndexName: "EmailIndex",
  KeyConditionExpression: "email__hmac = :e",
  ExpressionAttributeValues: { ":e": hmac },
}))

const decrypted = await dynamo.bulkDecryptModels(queryResult.Items ?? [], users)
```
