# @cipherstash/schema

A TypeScript schema builder for CipherStash encryption that enables you to define encryption schemas with searchable encryption capabilities.

## Overview

`@cipherstash/schema` is a standalone package that provides the schema building functionality used by `@cipherstash/protect`. While not required for typical usage, this package is available if you need to build encryption configuration schemas directly or want to understand the underlying schema structure.

> [!TIP]
> For new projects we recommend [`@cipherstash/stack`](https://www.npmjs.com/package/@cipherstash/stack), which exposes this functionality as `encryptedTable` / `encryptedColumn` from `@cipherstash/stack/schema`. The `csTable` / `csColumn` API documented below is the legacy naming used by `@cipherstash/protect`.

## Installation

```bash
npm install @cipherstash/schema
# or
yarn add @cipherstash/schema
# or
pnpm add @cipherstash/schema
```

## Quick Start

```typescript
import { csTable, csColumn, buildEncryptConfig } from '@cipherstash/schema'

// Define your schema
const users = csTable('users', {
  email: csColumn('email').freeTextSearch().equality().orderAndRange(),
  name: csColumn('name').freeTextSearch(),
  age: csColumn('age').orderAndRange(),
})

// Build the encryption configuration
const config = buildEncryptConfig(users)
console.log(config)
```

## Core Functions

### `csTable(tableName, columns)`

Creates a table definition with encrypted columns.

```typescript
import { csTable, csColumn } from '@cipherstash/schema'

const users = csTable('users', {
  email: csColumn('email'),
  name: csColumn('name'),
})
```

### `csColumn(columnName)`

Creates a column definition with configurable indexes and data types.

```typescript
import { csColumn } from '@cipherstash/schema'

const emailColumn = csColumn('email')
  .freeTextSearch()    // Enable text search
  .equality()          // Enable exact matching
  .orderAndRange()     // Enable sorting and range queries
  .dataType('string')  // Set data type
```

### `csValue(valueName)`

Creates a value definition for nested objects (up to 3 levels deep).

```typescript
import { csTable, csColumn, csValue } from '@cipherstash/schema'

const users = csTable('users', {
  email: csColumn('email').equality(),
  profile: {
    name: csValue('profile.name'),
    address: {
      street: csValue('profile.address.street'),
      location: {
        coordinates: csValue('profile.address.location.coordinates'),
      },
    },
  },
})
```

### `buildEncryptConfig(...tables)`

Builds the final encryption configuration from table definitions.

```typescript
import { buildEncryptConfig } from '@cipherstash/schema'

const config = buildEncryptConfig(users, orders, products)
```

## Index Types

### Equality Index (`.equality()`)

Enables exact matching queries.

```typescript
const emailColumn = csColumn('email').equality()
// SQL equivalent: WHERE email = 'example@example.com'
```

### Free Text Search (`.freeTextSearch()`)

Enables text search with configurable options.

```typescript
const descriptionColumn = csColumn('description').freeTextSearch({
  tokenizer: { kind: 'ngram', token_length: 3 },
  token_filters: [{ kind: 'downcase' }],
  k: 6,
  m: 2048,
  include_original: true,
})
// SQL equivalent: WHERE description LIKE '%example%'
```

### Order and Range (`.orderAndRange()`)

Enables sorting and range queries.

```typescript
const priceColumn = csColumn('price').orderAndRange()
// SQL equivalent: ORDER BY price ASC, WHERE price > 100
```

## Data Types

Set the data type for a column using `.dataType()`:

```typescript
const column = csColumn('field')
  .dataType('string')    // text (default)
  .dataType('number')    // Javascript number (i.e. integer or float)
  .dataType('jsonb')     // JSON binary
```

## Nested Objects

Support for nested object encryption (up to 3 levels deep):

```typescript
const users = csTable('users', {
  email: csColumn('email').equality(),
  profile: {
    name: csValue('profile.name'),
    address: {
      street: csValue('profile.address.street'),
      city: csValue('profile.address.city'),
      location: {
        coordinates: csValue('profile.address.location.coordinates'),
      },
    },
  },
})
```

> **Note**: Nested objects are not searchable and are not recommended for SQL databases. Use separate columns for searchable fields.

## Advanced Configuration

### Custom Token Filters

```typescript
const column = csColumn('field').equality([
  { kind: 'downcase' }
])
```

### Custom Match Options

```typescript
const column = csColumn('field').freeTextSearch({
  tokenizer: { kind: 'standard' },
  token_filters: [{ kind: 'downcase' }],
  k: 8,
  m: 4096,
  include_original: false,
})
```

## Type Safety

The schema builder provides full TypeScript support:

```typescript
import { csTable, csColumn, type ProtectTableColumn } from '@cipherstash/schema'

const users = csTable('users', {
  email: csColumn('email').equality(),
  name: csColumn('name').freeTextSearch(),
} as const)

// TypeScript will infer the correct types
type UsersTable = typeof users
```

## Integration with Protect.js

While this package can be used standalone, it's typically used through `@cipherstash/protect`:

```typescript
import { csTable, csColumn } from '@cipherstash/protect'

const users = csTable('users', {
  email: csColumn('email').equality().freeTextSearch(),
})

const protectClient = await protect({
  schemas: [users],
})
```

## Generated Configuration

The `buildEncryptConfig` function generates a configuration object like this:

```typescript
{
  v: 2,
  tables: {
    users: {
      email: {
        cast_as: 'text',
        indexes: {
          unique: { token_filters: [] },
          match: {
            tokenizer: { kind: 'ngram', token_length: 3 },
            token_filters: [{ kind: 'downcase' }],
            k: 6,
            m: 2048,
            include_original: true,
          },
          ore: {},
        },
      },
    },
  },
}
```

## Use Cases

- **Standalone schema building**: When you need to generate encryption configurations outside of Protect.js
- **Custom tooling**: Building tools that work with CipherStash encryption schemas
- **Schema validation**: Validating schema structures before using them with Protect.js
- **Documentation generation**: Creating documentation from schema definitions

## API Reference

### `csTable(tableName: string, columns: ProtectTableColumn)`

Creates a table definition.

**Parameters:**
- `tableName`: The name of the table in the database
- `columns`: Object defining the columns and their configurations

**Returns:** `ProtectTable<T> & T`

### `csColumn(columnName: string)`

Creates a column definition.

**Parameters:**
- `columnName`: The name of the column in the database

**Returns:** `ProtectColumn`

**Methods:**
- `.dataType(castAs: CastAs)`: Set the data type
- `.equality(tokenFilters?: TokenFilter[])`: Enable equality index
- `.freeTextSearch(opts?: MatchIndexOpts)`: Enable text search
- `.orderAndRange()`: Enable order and range index
- `.searchableJson()`: Enable searchable JSON index

### `csValue(valueName: string)`

Creates a value definition for nested objects.

**Parameters:**
- `valueName`: Dot-separated path to the value (e.g., 'profile.name')

**Returns:** `ProtectValue`

**Methods:**
- `.dataType(castAs: CastAs)`: Set the data type

### `buildEncryptConfig(...tables: ProtectTable[])`

Builds the encryption configuration.

**Parameters:**
- `...tables`: Variable number of table definitions

**Returns:** `EncryptConfig`

## License

MIT License - see [LICENSE.md](../../LICENSE.md) for details.
