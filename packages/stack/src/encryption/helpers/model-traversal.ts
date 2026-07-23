import { isEncryptedPayload } from '@/encryption/helpers'
import { assertValidNumericValue } from '@/encryption/helpers/validation'
import type { BuildableTable } from '@/types'

/**
 * The pure model-traversal layer shared by BOTH encryption entries: the
 * native model helpers (`./model-helpers`, which pair it with the NAPI
 * `encryptBulk`/`decryptBulk`) and the WASM entry (`@/wasm-inline`, which
 * pairs it with the `/wasm-inline` FFI batch calls — #742).
 *
 * Extracted so the walk itself cannot drift between entries. The traversal is
 * where the quiet plaintext-leak class of bug lives — a schema field the walk
 * fails to match is passed through UNENCRYPTED — so there must be exactly one
 * implementation of it.
 *
 * MUST stay free of runtime `@cipherstash/protect-ffi` imports (type-only is
 * fine): this module is bundled into `dist/wasm-inline.js`, whose whole point
 * is to not touch the native binding. `__tests__/wasm-inline-bundle-isolation`
 * enforces that at the artifact level.
 */

/**
 * Sets a value at a nested path in an object, creating intermediate objects as needed.
 * Includes prototype pollution protection.
 */
export function setNestedValue(
  obj: Record<string, unknown>,
  path: string[],
  value: unknown,
): void {
  const FORBIDDEN_KEYS = ['__proto__', 'prototype', 'constructor']
  let current: Record<string, unknown> = obj
  for (let i = 0; i < path.length - 1; i++) {
    const part = path[i]
    if (FORBIDDEN_KEYS.includes(part)) {
      throw new Error(`[encryption]: Forbidden key "${part}" in field path`)
    }
    if (
      !(part in current) ||
      typeof current[part] !== 'object' ||
      current[part] === null
    ) {
      current[part] = {}
    }
    current = current[part] as Record<string, unknown>
  }
  const lastKey = path[path.length - 1]
  if (FORBIDDEN_KEYS.includes(lastKey)) {
    throw new Error(`[encryption]: Forbidden key "${lastKey}" in field path`)
  }
  current[lastKey] = value
}

/**
 * Resolve how a table's model fields map onto encrypt-config columns.
 *
 * `columnPaths` are the keys used to MATCH a user model's fields (the JS
 * property names); `toColumnName` maps a matched field to the name the FFI /
 * encrypt config is keyed by (the DB name).
 *
 * When a table exposes `buildColumnKeyMap()` (v3), those two can differ, so we
 * match by property but address by DB name. Otherwise (v2) `build()` already
 * keys columns by the property name, so both are that same key (identity map).
 */
export function resolveEncryptColumnMap(table: BuildableTable): {
  columnPaths: string[]
  toColumnName: (path: string) => string
} {
  const keyMap = table.buildColumnKeyMap?.()
  if (keyMap) {
    return {
      columnPaths: Object.keys(keyMap),
      toColumnName: (path) => keyMap[path] ?? path,
    }
  }
  const columnPaths = Object.keys(table.build().columns)
  return { columnPaths, toColumnName: (path) => path }
}

// ---------------------------------------------------------------------------
// The non-mutating walk (#742 review)
// ---------------------------------------------------------------------------
//
// The previous walk shallow-copied the model (`{ ...model }`) and then
// `delete`d each matched field out of the copy. Because a shallow copy shares
// every nested object with the caller, that `delete` mutated the CALLER's
// input — and on a decrypt the sibling rebuild wrote decrypted PLAINTEXT back
// into the object the caller believed was still encrypted. Locating the field
// to delete meant re-`split('.')`-ing the dotted key and walking from the copy,
// which crashed (or leaked plaintext) on a literal flat dotted key and could
// reach `Object.prototype` via a `__proto__.x` key.
//
// This builder never touches the input. It returns a FRESH tree that omits the
// operation fields and keeps nulls / passthrough values in place, so:
//  - the caller's model is never mutated (no shared nested object is written);
//  - a literal flat dotted key is simply omitted, not re-split — no crash, no
//    surviving plaintext, no `Object.prototype` reach;
//  - nulls stay where they sit, so a dotted null key no longer materialises a
//    phantom nested object on rebuild (the rebuild no longer re-applies a
//    separate null map).

/**
 * True only for a plain object (`{}` / `Object.create(null)`) or an array —
 * the containers the walk descends into and clones. A `Date`, or any other
 * class instance, is NOT a container: cloning it by iterating its enumerable
 * keys would rebuild it as an empty `{}` (a `Date` has none), destroying the
 * value. Those pass through by reference instead (they are never mutated).
 */
function isPlainContainer(value: object): boolean {
  if (Array.isArray(value)) return true
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

interface WalkHooks {
  /** True when this field should be handed to the FFI (a schema column on
   *  encrypt, an EQL payload on decrypt) and omitted from the passthrough
   *  tree. */
  isOperationField: (fullKey: string, value: unknown) => boolean
  /** True when the walk should descend into this object because a schema
   *  column lives under it (always true on the schema-blind decrypt walk). */
  shouldRecurse: (fullKey: string) => boolean
  /** Receives each operation field in visit order. */
  onOperationField: (fullKey: string, value: unknown) => void
}

/**
 * Reject a top-level model that is not a plain record. A shallow-spread of a
 * string (`{ ...'x@y' }`) explodes into a char-indexed object and a
 * number/boolean into `{}`, which the old walk returned as a successful (but
 * silently wrong) result; fail loudly instead (#742 review).
 */
function assertModelObject(
  model: unknown,
): asserts model is Record<string, unknown> {
  if (typeof model !== 'object' || model === null || Array.isArray(model)) {
    throw new Error('[encryption]: each model must be a non-null object')
  }
}

/**
 * Pre-FFI guards for a value about to be encrypted from the model path (the
 * single/query paths guard at their own boundary). Out-of-range numbers and an
 * invalid `Date` (`new Date(NaN)`) are rejected here, per field, so the failure
 * names the column rather than surfacing as one coordinate-less batch error
 * from inside the FFI.
 */
function assertEncryptableValue(value: unknown, fullKey: string): void {
  assertValidNumericValue(value)
  if (value instanceof Date && Number.isNaN(value.getTime())) {
    throw new Error(
      `[encryption]: field "${fullKey}" is an invalid Date and cannot be encrypted`,
    )
  }
}

/**
 * Walk `obj`, returning a fresh passthrough tree that OMITS every operation
 * field and streams those fields to `hooks.onOperationField` in visit order.
 * Arrays are preserved as arrays. Never mutates `obj`.
 */
function buildPassthroughTree(
  obj: Record<string, unknown>,
  prefix: string,
  hooks: WalkHooks,
): unknown {
  const out: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key

    // Nulls carry no schema meaning and are never an operation — keep them in
    // place so the output shape matches the input exactly.
    if (value === null || value === undefined) {
      out[key] = value
      continue
    }

    if (hooks.isOperationField(fullKey, value)) {
      hooks.onOperationField(fullKey, value)
      // Omitted from `out`; the caller places the FFI result back here.
      continue
    }

    if (
      typeof value === 'object' &&
      isPlainContainer(value) &&
      !isEncryptedPayload(value) &&
      hooks.shouldRecurse(fullKey)
    ) {
      out[key] = buildPassthroughTree(
        value as Record<string, unknown>,
        fullKey,
        hooks,
      )
    } else {
      // Passthrough: a scalar, a Date / class instance, an already-encrypted
      // payload the schema didn't claim, or a plain object with no schema
      // column beneath it. Not mutated, so sharing the reference is safe.
      out[key] = value
    }
  }

  // Preserve array shape. An operation field inside an array is omitted,
  // leaving a hole at that index; the caller sets the FFI result back by path.
  if (Array.isArray(obj)) {
    const arr: unknown[] = []
    for (const [key, value] of Object.entries(out)) {
      arr[Number(key)] = value
    }
    return arr
  }
  return out
}

/** Recurse into an object only when a schema column lives at or under it. */
function encryptShouldRecurse(
  columnPaths: readonly string[],
): (fullKey: string) => boolean {
  return (fullKey) =>
    columnPaths.some(
      (path) => path === fullKey || path.startsWith(`${fullKey}.`),
    )
}

/**
 * Helper function to prepare fields for decryption
 */
export function prepareFieldsForDecryption<T extends Record<string, unknown>>(
  model: T,
): {
  otherFields: Record<string, unknown>
  operationFields: Record<string, unknown>
  keyMap: Record<string, string>
  nullFields: Record<string, null | undefined>
} {
  assertModelObject(model)
  const operationFields: Record<string, unknown> = {}
  const keyMap: Record<string, string> = {}
  let index = 0

  // Top-level model is a non-array object (asserted above), so the tree is a
  // Record; `buildPassthroughTree` returns `unknown` only to type its array arm.
  const otherFields = buildPassthroughTree(model, '', {
    isOperationField: (_fullKey, value) => isEncryptedPayload(value),
    shouldRecurse: () => true,
    onOperationField: (fullKey, value) => {
      keyMap[index.toString()] = fullKey
      operationFields[fullKey] = value
      index++
    },
  }) as Record<string, unknown>

  // Nulls are retained in `otherFields` in place, so no separate null map is
  // re-applied on rebuild (which is what materialised phantom nested objects).
  return { otherFields, operationFields, keyMap, nullFields: {} }
}

/**
 * Helper function to prepare fields for encryption
 */
export function prepareFieldsForEncryption<T extends Record<string, unknown>>(
  model: T,
  table: BuildableTable,
): {
  otherFields: Record<string, unknown>
  operationFields: Record<string, unknown>
  keyMap: Record<string, string>
  nullFields: Record<string, null | undefined>
} {
  assertModelObject(model)
  const { columnPaths } = resolveEncryptColumnMap(table)
  const columnSet = new Set(columnPaths)
  const operationFields: Record<string, unknown> = {}
  const keyMap: Record<string, string> = {}
  let index = 0

  const otherFields = buildPassthroughTree(model, '', {
    // Skip a value that is ALREADY an EQL payload even at a schema path — it
    // has been encrypted before (a read-modify-write of a fetched row); the
    // old walk re-encrypted it, silently for a `types.Json` column (#742).
    isOperationField: (fullKey, value) =>
      columnSet.has(fullKey) && !isEncryptedPayload(value),
    shouldRecurse: encryptShouldRecurse(columnPaths),
    onOperationField: (fullKey, value) => {
      assertEncryptableValue(value, fullKey)
      keyMap[index.toString()] = fullKey
      operationFields[fullKey] = value
      index++
    },
  }) as Record<string, unknown>

  return { otherFields, operationFields, keyMap, nullFields: {} }
}

/**
 * Helper function to prepare multiple models for bulk operation
 */
export function prepareBulkModelsForOperation<
  T extends Record<string, unknown>,
>(
  models: T[],
  table?: BuildableTable,
): {
  otherFields: Record<string, unknown>[]
  operationFields: Record<string, unknown>[]
  keyMap: Record<string, { modelIndex: number; fieldKey: string }>
  nullFields: Record<string, null | undefined>[]
} {
  const otherFields: Record<string, unknown>[] = []
  const operationFields: Record<string, unknown>[] = []
  const keyMap: Record<string, { modelIndex: number; fieldKey: string }> = {}
  let index = 0

  // Column paths are row-invariant, so resolve the map once for the whole batch
  // rather than once per model (the old walk rebuilt it inside the loop).
  const columnPaths = table ? resolveEncryptColumnMap(table).columnPaths : []
  const columnSet = new Set(columnPaths)
  const shouldRecurse = table ? encryptShouldRecurse(columnPaths) : () => true
  const isOperationField = table
    ? (fullKey: string, value: unknown) =>
        columnSet.has(fullKey) && !isEncryptedPayload(value)
    : (_fullKey: string, value: unknown) => isEncryptedPayload(value)

  for (let modelIndex = 0; modelIndex < models.length; modelIndex++) {
    const model = models[modelIndex]
    assertModelObject(model)
    const modelOperationFields: Record<string, unknown> = {}

    const tree = buildPassthroughTree(model, '', {
      isOperationField,
      shouldRecurse,
      onOperationField: (fullKey, value) => {
        // Only the encrypt walk validates; the decrypt walk collects payloads.
        if (table) assertEncryptableValue(value, fullKey)
        keyMap[index.toString()] = { modelIndex, fieldKey: fullKey }
        modelOperationFields[fullKey] = value
        index++
      },
    }) as Record<string, unknown>

    otherFields.push(tree)
    operationFields.push(modelOperationFields)
  }

  return {
    otherFields,
    operationFields,
    keyMap,
    nullFields: models.map(() => ({})),
  }
}

/**
 * Collect the per-model fields out of a bulk-operation result map keyed by
 * `${modelIndex}-${fieldKey}` ids, splitting each id at the FIRST hyphen
 * only. Field keys may themselves contain hyphens (a `some-field` column, or
 * a nested `profile.some-field` path), so a naive `split('-')` would truncate
 * the field key at its first hyphen and silently drop the value during model
 * reconstruction.
 */
export function fieldsForModelIndex(
  fields: Record<string, unknown>,
  modelIndex: number,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [id, value] of Object.entries(fields)) {
    const sep = id.indexOf('-')
    if (Number.parseInt(id.slice(0, sep), 10) !== modelIndex) continue
    result[id.slice(sep + 1)] = value
  }
  return result
}
