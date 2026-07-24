/**
 * The wire-format detection matrix behind `Encryption({ schemas })`.
 *
 * `resolveEqlVersion` decides, from the schema set alone, which EQL wire format
 * the FFI client will emit. It carries an `@internal exported for unit-test
 * coverage of the detection matrix` marker — this file is that coverage. It had
 * none until now, which mattered: the only place the v3 wire choice was
 * exercised was `integration/shared/v2-decrypt-compat.integration.test.ts`, and
 * that suite needs live ZeroKMS credentials, so a regression here was invisible
 * to `pnpm test`.
 *
 * Why a silent regression here is dangerous rather than merely wrong: if v3
 * detection broke, `resolveEqlVersion` would return `undefined` (the FFI's v2
 * default) instead of throwing, so a v3-schema client would quietly start
 * writing v2 wire into `eql_v3_*` columns. Every v2-read compatibility test
 * would keep passing, because reading v2 is exactly what a v2-mode client does
 * natively. Pin the mapping directly.
 *
 * Credential-free by construction: `resolveEqlVersion` is pure, and inspects
 * only `build()` output and the `buildColumnKeyMap` marker.
 */
import { describe, expect, it } from 'vitest'
import { resolveEqlVersion } from '@/encryption'
import { encryptedTable as encryptedTableV3, types as typesV3 } from '@/eql/v3'
// The deprecated v2 authoring builders remain for reading/migrating legacy data.
import { encryptedColumn, encryptedTable } from '@/schema'

const usersV3 = encryptedTableV3('users_v3', {
  email: typesV3.TextSearch('email'),
})

const ordersV3 = encryptedTableV3('orders_v3', {
  total: typesV3.IntegerOrd('total'),
})

const usersV2 = encryptedTable('users_v2', {
  email: encryptedColumn('email').equality(),
})

const documentsV2SteVec = encryptedTable('documents_v2', {
  metadata: encryptedColumn('metadata').searchableJson(),
})

describe('resolveEqlVersion — wire format detection', () => {
  it('resolves an all-v3 schema set to 3', () => {
    expect(resolveEqlVersion([usersV3])).toBe(3)
  })

  it('resolves several v3 tables to 3', () => {
    expect(resolveEqlVersion([usersV3, ordersV3])).toBe(3)
  })

  it('leaves a v2 scalar schema set on the FFI default by returning undefined', () => {
    // NOT `2`: the FFI's own default is v2, and `undefined` is what the client
    // passes through to mean "don't override it".
    expect(resolveEqlVersion([usersV2])).toBeUndefined()
  })

  it('throws on a mixed v2 + v3 schema set — one client emits one wire format', () => {
    expect(() => resolveEqlVersion([usersV3, usersV2])).toThrow(
      /cannot mix EQL v2 and EQL v3 tables in one client/,
    )
  })

  it('throws on a mixed set regardless of schema order', () => {
    expect(() => resolveEqlVersion([usersV2, usersV3])).toThrow(
      /cannot mix EQL v2 and EQL v3 tables in one client/,
    )
  })
})

describe('resolveEqlVersion — legacy v2 searchable JSON', () => {
  it('throws for a v2 ste_vec column, which protect-ffi 0.30 cannot emit', () => {
    expect(() => resolveEqlVersion([documentsV2SteVec])).toThrow(
      /searchableJson\(\) on the legacy EQL v2 schema is not supported/,
    )
  })

  it('still throws when an explicit eqlVersion is supplied', () => {
    // The explicit escape hatch bypasses DETECTION, not validation — otherwise
    // it would emit v3 data into an eql_v2 column.
    expect(() => resolveEqlVersion([documentsV2SteVec], 2)).toThrow(
      /searchableJson\(\) on the legacy EQL v2 schema is not supported/,
    )
  })
})

describe('resolveEqlVersion — explicit config.eqlVersion', () => {
  it('honours an explicit 2 over v3 schemas, for minting v2 wire during a migration', () => {
    expect(resolveEqlVersion([usersV3], 2)).toBe(2)
  })

  it('honours an explicit 3 over a v2 schema set', () => {
    expect(resolveEqlVersion([usersV2], 3)).toBe(3)
  })

  it('does not let an explicit version rescue a mixed schema set', () => {
    // Mixing is unfixable by declaration: the two generations target different
    // column types, so no single wire format serves both.
    expect(() => resolveEqlVersion([usersV3, usersV2], 3)).toThrow(
      /cannot mix EQL v2 and EQL v3 tables in one client/,
    )
  })
})
