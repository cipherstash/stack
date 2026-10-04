# JSONB Troubleshooting Guide

Common issues, error messages, and solutions for JSONB operations in protectjs-ffi.

## Table of Contents

1. [Common Error Messages](#common-error-messages)
2. [Type Mismatch Debugging](#type-mismatch-debugging)
3. [Query Returns No Results](#query-returns-no-results)
4. [Performance Considerations](#performance-considerations)
5. [Verification Steps](#verification-steps)

---

## Common Error Messages

Note: async API errors carry a stable `code` on the thrown `Error`, so you can branch on that instead of matching these messages.

### "Unsupported conversion from X to Y"

**Example:**
```
Error: Unsupported conversion from "String" to JsonB
```

**Cause:** Attempting to use a string value where JSON is required, or vice versa.

**Solutions:**

| Scenario | Problem | Solution |
|----------|---------|----------|
| `ste_vec_term` with JSON | Ordering term requires a string or number | Use `default` for containment |
| Path query with object | Selector requires string | Convert to JSONPath string (`$.user.name`) |
| Storage with wrong type | Column expects different type | Check `cast_as` in config |

**Choose the operation that matches the query:**
```typescript
// Ordering comparison against an extracted entry
await encryptQuery(client, {
  plaintext: 'admin',
  queryOp: 'ste_vec_term'
})

// Containment
await encryptQuery(client, {
  plaintext: { user: { role: 'admin' } },
  queryOp: 'default'
})
```

---

### "Cannot use X as SteVec query"

**Example:**
```
Error: Cannot use Number as SteVec query - use string for path queries or object/array for containment
```

**Cause:** Passing a primitive type (number, boolean) to a SteVec query with `queryOp: 'default'`.

**Valid types for SteVec queries:**
- String: Path selector queries
- Object: Containment queries
- Array: Containment queries

**Fix:**
```typescript
// Wrong - number doesn't make sense for SteVec
await encryptQuery(client, {
  plaintext: 42,
  indexType: 'ste_vec',
  queryOp: 'default'
})

// Correct - wrap in containment structure
await encryptQuery(client, {
  plaintext: { count: 42 },
  indexType: 'ste_vec',
  queryOp: 'default'
})
```

---

### "index type 'ste_vec' not configured for this column"

**Cause:** Attempting to query a JSON column that doesn't have a `ste_vec` index.

**Check your config:**
```typescript
// Missing ste_vec index
{
  cast_as: 'json',
  indexes: {}  // No ste_vec!
}

// Correct
{
  cast_as: 'json',
  indexes: {
    ste_vec: { prefix: 'table/column' }
  }
}
```

---

### "column X.Y not found in Encrypt config"

**Cause:** The table/column combination doesn't exist in your `EncryptConfig`.

**Verify config structure:**
```typescript
const config = {
  v: 1,
  tables: {
    users: {         // Table name must match
      profile: {     // Column name must match
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'users/profile' } }
      }
    }
  }
}

// Request must use matching names
await encrypt(client, {
  plaintext: { ... },
  table: 'users',    // Must match config
  column: 'profile'  // Must match config
})
```

---

### "Unknown query_op: X"

**Cause:** Invalid `queryOp` value.

**Valid values:**
- `'default'` - Infers from plaintext type
- `'ste_vec_selector'` - Path queries
- `'ste_vec_value_selector'` - Exact scalar equality at a path
- `'ste_vec_term'` - String/number ordering comparisons

---

## Type Mismatch Debugging

### Debugging Checklist

1. **Check `cast_as` in config**
   ```typescript
   // For JSONB columns
   cast_as: 'json'  // Required
   ```

2. **Check plaintext type**
   ```typescript
   // Use typeof to verify
   console.log(typeof plaintext)
   // 'string' | 'number' | 'boolean' | 'object'
   ```

3. **Check queryOp matches plaintext**
   | queryOp | Expected Plaintext |
   |---------|-------------------|
   | `ste_vec_selector` | string (JSONPath) |
   | `ste_vec_value_selector` | `{path, value}` with a scalar value |
   | `ste_vec_term` | string or number |
   | `default` | inferred from type |

### Common Type Issues

**Issue: String that looks like JSON**
```typescript
// Wrong - this is a string, not JSON
const plaintext = '{"role": "admin"}'

// Correct - parse it first
const plaintext = JSON.parse('{"role": "admin"}')
// or
const plaintext = { role: 'admin' }
```

**Issue: Array vs object confusion**
```typescript
// Arrays work for containment too
await encryptQuery(client, {
  plaintext: ['admin', 'moderator'],  // Array is valid
  queryOp: 'default'
})
```

---

### Exact "Path + Value" Queries

Use `ste_vec_value_selector` with exactly `{path, value}` when you need exact
equality for one scalar at one JSON path:

```typescript
await encryptQuery(client, {
  plaintext: { path: '$.user.role', value: 'admin' },
  queryOp: 'ste_vec_value_selector'
})
```

The result is a one-entry selector-only containment needle. For objects or
arrays, use a regular `default` containment query instead.

---

## Query Returns No Results

### Debugging Steps

#### 1. Verify Data Was Stored Correctly

```typescript
// Encrypt and decrypt to verify
const ciphertext = await encrypt(client, {
  plaintext: { user: { role: 'admin' } },
  table: 'users',
  column: 'profile'
})

const decrypted = await decrypt(client, { ciphertext })
console.log(decrypted)  // Should match input
```

#### 2. Check Query Structure Matches Storage

The query structure must be a **subset** of the stored structure for containment:

```typescript
// Stored
{ user: { role: 'admin', name: 'alice' } }

// This query matches (subset)
{ user: { role: 'admin' } }

// This query does NOT match (different structure)
{ role: 'admin' }  // Missing 'user' wrapper
```

#### 3. Verify Selector Path Exists

For path queries, the path must exist in the stored data:

```typescript
// Stored
{ user: { name: 'alice' } }

// This selector works
'$.user.name'

// This selector won't find anything
'$.user.email'  // Path doesn't exist
```

#### 4. Check Array Containment

Array containment in PostgreSQL/EQL follows specific rules:

```typescript
// Stored
{ tags: ['admin', 'moderator', 'user'] }

// This matches (subset array)
{ tags: ['admin'] }

// This matches (subset array with multiple)
{ tags: ['admin', 'user'] }

// This does NOT match (order matters for exact)
{ tags: ['user', 'admin'] }  // Different order
```

### Using SQL to Debug

```sql
-- Check raw data
SELECT id, profile FROM users LIMIT 5;

-- Test containment manually
SELECT * FROM users
WHERE profile @> '{"user": {"role": "admin"}}'::jsonb;

-- Test path existence
SELECT * FROM users
WHERE eql_v2.jsonb_path_exists(profile, $selector);
```

---

## Performance Considerations

### Index Size

SteVec indexes grow with JSON complexity:

| JSON Structure | Approximate Entries |
|---------------|---------------------|
| `{ a: 1 }` | 1 entry |
| `{ a: 1, b: 2, c: 3 }` | 3 entries |
| `{ a: { b: { c: 1 } } }` | 1 entry (deep path) |
| `{ items: [1, 2, 3, 4, 5] }` | 5 entries |

**Recommendation:** Flatten deeply nested structures or use targeted indexing.

### Query Complexity

| Query Type | Performance |
|------------|-------------|
| Simple key match | Fast |
| Nested path | Moderate |
| Large array containment | Slower |
| Multiple OR conditions | Use bulk queries |

### Bulk Operations

For multiple queries, use bulk APIs:

```typescript
// Slower - individual queries
for (const term of terms) {
  await encryptQuery(client, { plaintext: term, ... })
}

// Faster - bulk query
await encryptQueryBulk(client, {
  queries: terms.map(term => ({ plaintext: term, ... }))
})
```

---

## Verification Steps

### Pre-Flight Checklist

Before debugging, verify:

- [ ] **Client initialized** with correct config
- [ ] **Column configured** with `cast_as: 'json'` and `ste_vec` index
- [ ] **Table/column names** match between config and API calls
- [ ] **Plaintext type** appropriate for operation
- [ ] **queryOp** matches intended behavior

### Encryption Output Verification

Check the output structure:

```typescript
const result = await encrypt(client, { plaintext, table, column })

console.log('Has identifier:', result.i !== undefined)
console.log('Has version:', result.v !== undefined)
console.log('Has ciphertext:', result.c !== undefined)
console.log('Has SteVec entries:', result.sv !== undefined)
console.log('SteVec count:', result.sv?.length ?? 0)
```

**Expected for storage:**
- `i`: Present (identifier)
- `v`: Present (version, usually 2)
- `c`: Present (encrypted JSON)
- `sv`: Present with entries

### Query Output Verification

**Selector query:**
```typescript
const result = await encryptQuery(client, {
  plaintext: '$.user.name',
  queryOp: 'ste_vec_selector',
  ...
})

console.log('Has selector:', result.s !== undefined)
console.log('Has ciphertext:', result.c !== undefined)  // Should be false
```

**Containment query:**
```typescript
const result = await encryptQuery(client, {
  plaintext: { role: 'admin' },
  queryOp: 'default',
  ...
})

console.log('Has SteVec:', result.sv !== undefined)
console.log('SteVec count:', result.sv?.length ?? 0)
```

### Integration Test Pattern

```typescript
test('round-trip encryption works', async () => {
  const client = await newClient({ encryptConfig })
  const original = { user: { role: 'admin', name: 'alice' } }

  // Storage
  const stored = await encrypt(client, {
    plaintext: original,
    table: 'users',
    column: 'profile'
  })
  expect(stored.sv).toBeDefined()
  expect(stored.c).toBeDefined()

  // Decryption
  const decrypted = await decrypt(client, { ciphertext: stored })
  expect(decrypted).toEqual(original)

  // Query - selector
  const selector = await encryptQuery(client, {
    plaintext: '$.user.name',
    table: 'users',
    column: 'profile',
    indexType: 'ste_vec',
    queryOp: 'ste_vec_selector'
  })
  expect(selector.s).toBeDefined()
  expect(selector.c).toBeUndefined()

  // Query - containment
  const term = await encryptQuery(client, {
    plaintext: { user: { role: 'admin' } },
    table: 'users',
    column: 'profile',
    indexType: 'ste_vec',
    queryOp: 'default'
  })
  expect(term.sv).toBeDefined()
})
```

---

## Related Documentation

- [Integration Guide](./jsonb-integration.md) - Architecture and data flow
- [API Reference](./jsonb-api-reference.md) - Detailed API documentation
