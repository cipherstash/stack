# JSONB API Reference

Complete API reference for JSONB operations in protectjs-ffi.

## Table of Contents

1. [Supported Operations](#supported-operations)
2. [Path Selector Syntax](#path-selector-syntax)
3. [QueryOp Types](#queryop-types)
4. [Output Structure](#output-structure)
5. [Type Inference Rules](#type-inference-rules)
6. [Schema Configuration](#schema-configuration)

---

## Supported Operations

### PostgreSQL to Encrypted Mapping

| PostgreSQL Operation | SQL Syntax | protectjs-ffi Approach |
|---------------------|------------|------------------------|
| Path selection | `column->'key'` | `encryptQuery` with selector |
| Path text | `column->>'key'` | `encryptQuery` with selector |
| Containment | `column @> '{"k":"v"}'` | `encryptQuery` with term |
| Contained by | `'{"k":"v"}' <@ column` | `encryptQuery` with term |
| Path exists | `column ? 'key'` | `encryptQuery` with selector |
| Nested path | `column->'a'->'b'` | `encryptQuery` with `$.a.b` |

### EQL v2 Functions

| Function | Purpose | Input Type |
|----------|---------|------------|
| `eql_v2.jsonb_path_query(col, sel)` | Select values at path | Selector |
| `eql_v2.jsonb_path_exists(col, sel)` | Check path exists | Selector |
| `eql_v2.jsonb_path_query_first(col, sel)` | First value at path | Selector |
| `eql_v2.ste_vec_contains(col, term)` | Containment check | Term |
| `col @> term` | Containment operator | Term |
| `term <@ col` | Contained by operator | Term |
| `eql_v2.jsonb_array_length(col)` | Array length | - |
| `eql_v2.jsonb_array_elements(col)` | Expand array to rows | - |
| `eql_v2.jsonb_array_elements_text(col)` | Expand array to text rows | - |

**Security Note:** Selectors can be passed as plaintext JSONPath strings (e.g., `'$.user.email'`) but this is **less secure** than using encrypted selectors from `encryptQuery`. Always prefer encrypted selectors in production.

---

## Path Selector Syntax

Path selectors use a subset of JSONPath syntax (eJsonPath).

### Selector Components

| Component | Syntax | Example |
|-----------|--------|---------|
| Root | `$` | `$` (matches root) |
| Dot notation | `.key` | `$.user` |
| Bracket notation | `['key']` | `$['user-name']` |
| Array index | `[n]` | `$.items[0]` |
| Nested path | `.a.b.c` | `$.user.profile.name` |

### Valid Path Examples

```javascript
// Simple key access
'$.name'

// Nested object access
'$.user.profile.email'

// Array element access
'$.items[0]'

// Mixed nesting
'$.users[0].profile.settings'

// Keys with special characters (use bracket notation)
"$['user-name']"
"$['@type']"
```

### Path Construction Rules

1. Paths **must** start with `$` (root selector)
2. Use dot notation for simple alphanumeric keys
3. Use bracket notation for keys with special characters
4. Array indices are zero-based integers

---

## QueryOp Types

The `queryOp` parameter controls how query encryption is performed.

### `default`

Automatically infers operation from plaintext type:

| Plaintext Type | Inferred Operation | Behavior |
|---------------|-------------------|----------|
| String | `ste_vec_selector` | Path query |
| Object | containment | Containment query |
| Array | containment | Containment query |
| Number | **Error** | Not supported |
| Boolean | **Error** | Not supported |

```typescript
// String → selector
await encryptQuery(client, {
  plaintext: '$.user.email',
  indexType: 'ste_vec',
  queryOp: 'default'  // Infers ste_vec_selector
})

// Object → containment needle
await encryptQuery(client, {
  plaintext: { role: 'admin' },
  indexType: 'ste_vec',
  queryOp: 'default'
})
```

### `ste_vec_selector`

Explicitly encrypts a JSONPath string for path queries.

**Input:** String (JSONPath like `$.user.email`)
**Output:** `{ i, v, s }` (selector only, no ciphertext)

```typescript
const selector = await encryptQuery(client, {
  plaintext: '$.user.name',
  table: 'users',
  column: 'profile',
  indexType: 'ste_vec',
  queryOp: 'ste_vec_selector'
})

// Use with: eql_v2.jsonb_path_query(profile, $selector)
```

### `ste_vec_value_selector`

Generates an exact-match selector for one scalar value at a JSON path.

**Input:** Exactly `{ path: string, value: string | number | boolean | null }`
**Output:** A one-entry, selector-only containment needle

```typescript
const needle = await encryptQuery(client, {
  plaintext: { path: '$.user.role', value: 'admin' },
  table: 'users',
  column: 'profile',
  indexType: 'ste_vec',
  queryOp: 'ste_vec_value_selector'
})

// EQL v3: profile @> $needle::jsonb::eql_v3.query_json
```

Objects and arrays are rejected because one selector cannot represent their
contents injectively; use `default` with the object or array for containment.

### `ste_vec_term`

Generates the order term for a string or number. This is for `<`, `<=`, `>`,
and `>=` comparisons against an entry extracted with a path selector. It is not
an exact-equality or containment operand; use `ste_vec_value_selector` for exact
equality and `default` with an object or array for containment.

---

## Output Structure

### EqlCiphertext Format

Scalar-only configurations retain the `eqlVersion: 2` default. A configuration
containing a `ste_vec` index defaults to EQL v3 because cipherstash-client 0.42
cannot emit the new selector-bound SteVec envelope as v2; explicitly requesting
`eqlVersion: 2` with such a configuration is rejected during client creation.
Clients using v3 return the shapes described in
[EQL v3 output](#eql-v3-output-eqlversion-3) below.

```typescript
type EqlCiphertext = EncryptedScalar | EncryptedSteVec

// k = "ct" — scalar payload
type EncryptedScalar = {
  k: 'ct'
  v: number                     // Version
  i: { t: string; c: string }  // Identifier (table, column)
  c: string                     // Encrypted ciphertext (mp_base85) — required for storage
  hm?: string                   // HMAC-SHA256 (unique index)
  bf?: number[]                 // Bloom filter (match index)
  ob?: string[]                 // Block ORE u64_8_256 (ore index)
}

// k = "sv" — STE-vector payload
type EncryptedSteVec = {
  k: 'sv'
  v: number                     // Version
  i: { t: string; c: string }  // Identifier (table, column)
  sv: SteVecEntry[]            // Per-selector entries; root ciphertext lives at sv[0].c
}

type SteVecEntry = {
  s: string       // Hex-encoded tokenized selector
  c: string       // Per-entry ciphertext (mp_base85) — required
  a?: boolean     // Array marker
  op?: string     // CLLW OPE ordering term — path entries for strings/numbers
  oc?: string     // CLLW ORE term — orderable leaves, Standard mode (EQL v2 only)
}
```

Query payloads share the same `{ k, v, i, ... }` shape but omit `c` at the root (queries do not encrypt for storage). For `k = "ct"` queries, the payload carries exactly one of `hm`, `bf`, or `ob`. For `k = "sv"`, path selectors carry a single tokenized `s`; exact value selectors and containment queries carry an `sv` array — see the *Output by Operation* table below.

Exact matching is encoded in value-inclusive selectors, so entries no longer
carry `hm`. String and number path entries additionally carry an ordering term:

| JSON value type | `compat` mode | `standard` mode |
|-----------------|---------------|-----------------|
| Object, array, boolean, null | no term | no term |
| String, number | `op` (CLLW OPE, tagged-plaintext) | `oc` (CLLW ORE, tagged-plaintext) |

Since `cipherstash-client` 0.40.0 the default is **`compat`** (`op`); it was `standard` (`oc`) before. Indexes produced under the two modes are **not cross-comparable**, so the indexing and query sides must agree, and a column whose existing rows were written under one mode must be re-encrypted to move to the other. Client 0.42 emits SteVec only in EQL v3 and only in `compat` mode.

Numeric and string values share the single orderable field — domain separation is enforced on the plaintext bit stream before encryption, so numeric ciphertexts always sort below string ciphertexts.

### Output by Operation

| Operation | Discriminator | Fields Present |
|-----------|---------------|----------------|
| Scalar storage (`encrypt` on non-JSON column) | `k: "ct"` | `k, v, i, c` + any of `hm, bf, ob` |
| SteVec storage (`encrypt` on JSON column) | `k: "sv"` | `k, v, i, sv` (root ciphertext at `sv[0].c`) |
| Scalar query (`encryptQuery` with `ore`/`match`/`unique`) | `k: "ct"` | `k, v, i` + one of `hm, bf, ob` |
| SteVec selector query (`encryptQuery` with `ste_vec_selector`) | `k: "sv"` | `k, v, i, s` |
| SteVec exact-value query (`ste_vec_value_selector`) | `k: "sv"` | one selector-only `sv` entry |
| SteVec containment query (`encryptQuery` with object/array input) | `k: "sv"` | `k, v, i, sv` |

### Example Outputs

**Scalar storage encryption (e.g. `email`, `score`):**
```json
{
  "k": "ct",
  "v": 2,
  "i": { "t": "users", "c": "email" },
  "c": "base85encodedciphertext...",
  "hm": "abc123...",
  "bf": [1, 2, 3]
}
```

**Legacy v2 SteVec storage payload (accepted for decryption only):**
```json
{
  "k": "sv",
  "v": 2,
  "i": { "t": "users", "c": "profile" },
  "sv": [
    { "s": "rootselector", "hm": "rootmac", "c": "rootciphertext..." },
    { "s": "abc123", "hm": "def456", "c": "..." },
    { "s": "jkl012", "op": "pqr678", "c": "..." }
  ]
}
```

**Legacy v2 selector query (not emitted by client 0.42):**
```json
{
  "k": "sv",
  "v": 2,
  "i": { "t": "users", "c": "profile" },
  "s": "abc123def456"
}
```

**Containment query (Compat mode, the default):**
```json
{
  "k": "sv",
  "v": 2,
  "i": { "t": "users", "c": "profile" },
  "sv": [
    { "s": "abc123", "op": "ghi789", "c": "..." }
  ]
}
```

### EQL v3 output (`eqlVersion: 3`)

Clients created with `newClient({ ..., eqlVersion: 3 })` emit the `eql_v3`
wire format instead. Scalar payloads carry no `k` discriminator (the
envelope is `{ v: 3, i, ... }` with the shape determined by the column's
`eql_v3` domain); SteVec documents keep `k: "sv"`.

**SteVec storage encryption (`public.eql_v3_json_search`):**
```json
{
  "v": 3,
  "k": "sv",
  "i": { "t": "users", "c": "profile" },
  "h": "document-key-header...",
  "sv": [
    { "s": "rootselector", "c": "rootciphertext..." },
    { "s": "abc123", "op": "ghi789", "c": "..." }
  ]
}
```

`h` stores the document key-retrieval material once. Each entry's `c` is raw
AEAD output, while its 16-byte selector supplies both the nonce and authenticated
additional data. `sv[0]` remains the **decryption root**; changing its selector,
ciphertext, or position causes authenticated decryption to fail.

**Containment query (`eql_v3.query_json` needle):**
```json
{
  "sv": [
    { "s": "abc123", "op": "ghi789" }
  ]
}
```

The needle carries no envelope (`v`/`i`) and no per-entry ciphertexts —
each entry is a selector plus an optional ordering `op`, mirroring the SQL
cast `eql_v3.to_ste_vec_query`. Use it with the `@>`/`<@` operators against
a `public.eql_v3_json_search` column (`WHERE doc @> $1::jsonb::eql_v3.query_json`).

v3 orders SteVec entries by the CLLW-OPE `op` term, so a JSON column's
`ste_vec` index must use the `compat` mode (the cipherstash-client default).
A `standard`-mode index emits CLLW-ORE `oc` terms, which v3 cannot represent —
protect-ffi rejects such a column at configuration time.

**Selector (path) query:** `encryptQuery` with `queryOp: 'ste_vec_selector'`
returns the bare selector hash as a **string** — there is no
encrypted-selector envelope in v3. Bind it as the `text` argument of the
`->` / `->>` operators (`SELECT doc -> $1::text`); it is the same
`Selector` encoding SteVec entries carry in `s`.

**Exact value query:** `encryptQuery` with
`queryOp: 'ste_vec_value_selector'` returns `{sv: [{s}]}` for
`{path, value}`. Bind it as `eql_v3.query_json` and use `@>` against the
encrypted JSON column. The GIN index can match the selector directly.

**Scalar queries:** supported under `eqlVersion: 3` since the release that
that introduced native v3 query operands — `encryptQuery` on a scalar column
returns the term-only operand (`{v, i, <terms>}`, no `c`) for the column
domain's `eql_v3.query_<name>` twin. See the README's EQL v3 section for
the domain/operator matrix.

---

## Type Inference Rules

### JsPlaintext Type Detection

The FFI receives JavaScript values and categorizes them:

| JavaScript Value | JsPlaintext Variant | Notes |
|-----------------|---------------------|-------|
| `"string"` | `String` | Strings |
| `42`, `3.14` | `Number` | All numbers (integers and floats) |
| `42n` | `BigInt` | Top-level scalar plaintexts only — i64-bounded, not valid inside JSON |
| `true`, `false` | `Boolean` | Booleans (supported for storage and decryption) |
| `{ key: val }` | `JsonB` | Objects |
| `[1, 2, 3]` | `JsonB` | Arrays |
| `null` | `JsonB` | JSON null |

### Conversion Rules

Type coercion follows strict rules (conversion allowed, parsing not; a
value that cannot be represented exactly in the target type errors instead
of being truncated):

| From | To | Result |
|------|----|--------|
| String | Utf8Str | Allowed |
| String | JsonB | **Error** |
| Number | Float | Allowed (including fractional and non-finite values) |
| Number | BigInt/Int/SmallInt/BigUInt | Allowed (errors on fractional / out-of-range / non-finite) |
| Number | Decimal | Allowed (errors on non-finite) |
| Number | Utf8Str | **Error** |
| BigInt | BigInt/Int/SmallInt/BigUInt/Decimal | Allowed (errors on out-of-range) |
| BigInt | Float/JsonB/Utf8Str | **Error** |
| Boolean | Boolean | Allowed |
| Boolean | Utf8Str | **Error** |
| JsonB | JsonB | Allowed |
| JsonB | Utf8Str | **Error** |

### Query Type Inference (SteVec)

For `ste_vec` index with `queryOp: 'default'`:

```
                    ┌─────────────────────┐
                    │  JsPlaintext type   │
                    └─────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌─────────┐    ┌─────────┐    ┌─────────┐
         │ String  │    │ JsonB   │    │ Number/ │
         │         │    │(obj/arr)│    │ Boolean │
         └─────────┘    └─────────┘    └─────────┘
              │               │               │
              ▼               ▼               ▼
         ┌─────────┐    ┌─────────┐    ┌─────────┐
         │Selector │    │  Term   │    │  ERROR  │
         │(Query)  │    │(Store)  │    │         │
         └─────────┘    └─────────┘    └─────────┘
```

---

## Schema Configuration

### EncryptConfig Structure

```typescript
type EncryptConfig = {
  v: number  // Version (always 1)
  tables: Record<string, Record<string, Column>>
}

type Column = {
  cast_as?:
    | 'bigint' | 'boolean' | 'date' | 'json'
    | 'number' | 'string' | 'text' | 'timestamp'
  indexes?: {
    ore?: {}
    unique?: { token_filters?: TokenFilter[] }
    match?: { tokenizer?: Tokenizer; k?: number; m?: number; include_original?: boolean }
    ste_vec?: {
      prefix: string
      term_filters?: TokenFilter[]
      array_index_mode?: ArrayIndexMode
      mode?: 'compat' | 'standard'
    }
  }
}
```

`match.include_original` is a storage-only option: it adds the whole
(filtered, untokenized) value as an extra bloom term so the stored filter can
also answer whole-value equality. It is never applied when generating query
terms — `encryptQuery` / `encryptQueryBulk` always emit token-only blooms, so
substring matching keeps working for columns that store whole-value terms.

### JSONB Column Configuration

For searchable JSONB columns, use:

```typescript
const config = {
  v: 1,
  tables: {
    users: {
      profile: {
        cast_as: 'json',  // Required for JSONB
        indexes: {
          ste_vec: {
            prefix: 'users/profile'  // Unique prefix per column
          }
        }
      }
    }
  }
}
```

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `v` | number | Yes | Config schema version. Must be `1`; other values fail at `newClient` with `UNSUPPORTED_CONFIG_VERSION`. |
| `cast_as` | string | Yes | Must be `'json'` for JSONB. See *cast_as vocabulary* below. |
| `indexes.ste_vec` | object | Yes* | Enables JSONB queries. Requires `cast_as: 'json'`; other values fail at `newClient` with `STE_VEC_REQUIRES_JSON_CAST_AS`. |
| `indexes.ste_vec.prefix` | string | Yes | Unique identifier for index |
| `indexes.ste_vec.term_filters` | array | No | Optional case normalization. Only `downcase` is valid for JSON; stemming and stop-word filters are rejected. |
| `indexes.ste_vec.array_index_mode` | string \| object | No | Controls how array elements are indexed. Defaults to `'none'`. |
| `indexes.ste_vec.mode` | string | No | Encoding mode: `'compat'` (default) or legacy `'standard'`. EQL v3 requires `'compat'`. |
| `indexes.match` | object | No | Full-text search index. Requires a text-family `cast_as` (`'text'` or `'string'`); other values fail at `newClient` with `MATCH_REQUIRES_TEXT`. |

*Required for path/containment queries. Without `ste_vec`, JSON is stored as opaque blob.

### cast_as vocabulary

The public `cast_as` union accepts a JS-friendly vocabulary. Three values are translated internally before reaching the native config; the remaining values pass through unchanged.

| Public value | Internal value | Notes |
|-------------|----------------|-------|
| `'string'` | `text` | Translated automatically |
| `'number'` | `float` | Translated automatically |
| `'bigint'` | `big_int` | Translated automatically |
| `'text'` | `text` | Pass-through |
| `'boolean'` | `boolean` | Pass-through |
| `'date'` | `date` | Pass-through |
| `'json'` | `json` | Pass-through; required for `ste_vec` indexes |
| `'timestamp'` | `timestamp` | Pass-through |

The translation happens in TypeScript at the `newClient` boundary and is invisible to callers.

### SteVec mode

The `mode` option controls the ordering term used for `ste_vec` path entries.
The default is `'compat'` (CLLW-OPE `op`), and EQL v3 requires it. The legacy
`'standard'` mode emits CLLW-ORE `oc`, which EQL v3 cannot represent.

**Warning:** changing `mode` on an existing column requires re-encrypting all stored data for that column; the two encodings are not cross-compatible.

### Opaque vs Searchable JSON

**Opaque (no queries):**
```typescript
{
  cast_as: 'json',
  indexes: {}
}
```

**Searchable (with queries):**
```typescript
{
  cast_as: 'json',
  indexes: {
    ste_vec: { prefix: 'table/column' }
  }
}
```

---

## Function Signatures

### newClient

```typescript
function newClient(opts: NewClientOptions): Promise<Client>

type NewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: {
    workspaceCrn?: string
    accessKey?: string
    clientId?: string
    clientKey?: string
    keyset?: { Uuid: string } | { Name: string }
  }
}
```

### encrypt / encryptBulk

```typescript
function encrypt(client: Client, opts: EncryptOptions): Promise<Encrypted>

type EncryptOptions = {
  plaintext: JsPlaintext
  table: string
  column: string
  lockContext?: { identityClaim: string[] }
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

function encryptBulk(
  client: Client,
  opts: { plaintexts: EncryptPayload[] }
): Promise<Encrypted[]>
```

### encryptQuery / encryptQueryBulk

```typescript
function encryptQuery(
  client: Client,
  opts: EncryptQueryOptions
): Promise<Encrypted>

type EncryptQueryOptions = {
  plaintext: JsPlaintext
  table: string
  column: string
  indexType: 'ste_vec' | 'match' | 'ore' | 'ope' | 'unique'
  queryOp?: 'default' | 'ste_vec_selector' | 'ste_vec_value_selector' | 'ste_vec_term'
  lockContext?: { identityClaim: string[] }
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

function encryptQueryBulk(
  client: Client,
  opts: { queries: QueryPayload[] }
): Promise<Encrypted[]>
```

### isEncrypted

```typescript
function isEncrypted(encrypted: Encrypted): boolean
```

Synchronously checks if a value is a valid encrypted ciphertext structure. Useful for conditionally processing data that may or may not be encrypted.

### decrypt / decryptBulk

```typescript
function decrypt(client: Client, opts: DecryptOptions): Promise<JsPlaintext>

function decryptBulk(
  client: Client,
  opts: { ciphertexts: BulkDecryptPayload[] }
): Promise<JsPlaintext[]>

function decryptBulkFallible(
  client: Client,
  opts: { ciphertexts: BulkDecryptPayload[] }
): Promise<DecryptResult[]>

type DecryptResult =
  | { data: JsPlaintext }
  | { error: string; code?: ProtectErrorCode }
```

### Errors

Both entries throw an ordinary JS `Error` carrying a stable `code`, set in Rust
from the error variant:

```typescript
Error & { code?: ProtectErrorCode }
```

There is no wrapper class. Rust builds the thrown error, so the two bindings
behave identically and the stack points at the call that failed rather than at
a wrapper.

The `ProtectErrorCode` values are not restated here — they were, and the copy
had already drifted (it was missing `SHORT_MATCH_NEEDLE`). They live in
`src/errors.ts` as `PROTECT_ERROR_CODES`, and `src/errorCodes.test.ts` checks
that list against the `#[diagnostic(code(..))]` attributes in
`crates/protect-ffi/src/lib.rs`, which is where a code is decided.

Not every failure has one. Errors that wrap a cipherstash-client failure carry
no code of their own and arrive without the field, and `DecryptResult` items
omit `code` rather than setting it to `'UNKNOWN'`. `'UNKNOWN'` stays in the
union as the name for that case.

TypeScript types a `catch` variable as `unknown`, so a caller narrows once.
Branching needs nothing from this package:

```typescript
try {
  await encryptQuery(client, opts)
} catch (err) {
  if (err instanceof Error && 'code' in err && err.code === 'INVALID_JSON_PATH') {
    // handle JSON path mistakes
  }
  throw err
}
```

To carry the code around as a typed value — storing it on a result object, say
— use `isProtectErrorCode`. It checks the value, not just the field's presence:
Node puts a `code` on its own errors, so a bare read would let an `ECONNRESET`
pass for one of these.

```typescript
import {
  isProtectErrorCode,
  type ProtectErrorCode,
} from '@cipherstash/protect-ffi'

function errorCode(err: unknown): ProtectErrorCode | undefined {
  const { code } = err as { code?: unknown }
  return isProtectErrorCode(code) ? code : undefined
}
```

---

## Related Documentation

- [Integration Guide](./jsonb-integration.md) - Architecture and data flow
- [Troubleshooting](./jsonb-troubleshooting.md) - Common issues and solutions
