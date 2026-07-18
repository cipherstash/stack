/**
 * Live-PG v2/v3 coexistence: a v2 client (`cipherstashFromStackV2`, v2
 * contract, `public.eql_v2_encrypted` composite wire) and a v3 client
 * (`cipherstashFromStack`, v3 contract, plain-JSONB domain wire)
 * running in the SAME process against the SAME database — each with
 * its own table, registry, descriptor, and middleware. Decision 1b:
 * the two generations never share a client; this suite proves the two
 * entry points coexist side by side without cross-talk (a mixed
 * v2+v3-columns client is unsupported and pinned as a hard error in
 * `from-stack-divergence-v3.test.ts`).
 *
 * The v2 half needs EQL v2 installed (the `local/` docker image ships
 * it preinstalled); it skips itself when `public.eql_v2_encrypted` is
 * absent so the suite stays runnable against a v3-only database.
 */

import 'dotenv/config'
import type { PostgresContract } from '@prisma-next/adapter-postgres/types'
import { validateSqlContractFully } from '@prisma-next/sql-contract/validators'
import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptedString } from '../../src/execution/envelope-string'
import type { CipherstashSdk } from '../../src/execution/sdk'
import {
  CIPHERSTASH_SPACE_ID,
  CIPHERSTASH_STRING_CODEC_ID,
} from '../../src/extension-metadata/constants'
import { CIPHERSTASH_V3_EXTENSION_VERSION } from '../../src/extension-metadata/constants-v3'
import { deriveStackSchemas } from '../../src/stack/derive-schemas'
import {
  type CipherstashFromStackResult,
  cipherstashFromStackV2,
} from '../../src/stack/from-stack'
import { createCipherstashSdk } from '../../src/stack/sdk-adapter'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
} from '../v3/operator-lowering-v3.helpers'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import {
  createLiveTable,
  decryptCell,
  insertEncryptedRows,
  type LiveV3Client,
  liveConnection,
  liveV3Contract,
  runLoweredSelect,
  selectIdsWhere,
  setupLiveV3,
  TEXT_SEARCH,
} from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const V2_TABLE = 'pn_live_side_v2'
const V3_TABLE = 'pn_live_side_v3'
const EQL_V2_ENCRYPTED_TYPE = 'public.eql_v2_encrypted'

const v2Contract = validateSqlContractFully<PostgresContract>({
  target: 'postgres',
  targetFamily: 'sql',
  profileHash: 'sha256:cipherstash-live-side-by-side-v2',
  roots: {},
  capabilities: {},
  extensionPacks: {},
  meta: {},
  storage: {
    storageHash: 'sha256:cipherstash-live-side-by-side-v2-storage',
    namespaces: {
      __unbound__: {
        id: '__unbound__',
        entries: {
          table: {
            [V2_TABLE]: {
              columns: {
                id: {
                  codecId: 'pg/text@1',
                  nativeType: 'text',
                  nullable: false,
                },
                email: {
                  codecId: CIPHERSTASH_STRING_CODEC_ID,
                  nativeType: EQL_V2_ENCRYPTED_TYPE,
                  nullable: true,
                },
              },
              uniques: [],
              indexes: [],
              foreignKeys: [],
            },
          },
        },
      },
    },
  },
  domain: { namespaces: { __unbound__: { models: {} } } },
})

const v3Contract = liveV3Contract(V3_TABLE, { email: TEXT_SEARCH })

const V2_EMAIL = 'v2-resident@example.com'
const V3_EMAIL = 'v3-resident@example.com'

describeLivePg('v2 and v3 clients side by side against live Postgres', () => {
  let sql: postgres.Sql
  let hasEqlV2 = false
  let v2: CipherstashFromStackResult | undefined
  let v2Sdk: CipherstashSdk | undefined
  let v3: LiveV3Client

  beforeAll(async () => {
    sql = liveConnection()
    await installEqlV3IfNeeded(sql)

    // v3 half — always available once the bundle is installed.
    await createLiveTable(sql, V3_TABLE, { email: TEXT_SEARCH })
    v3 = await setupLiveV3(v3Contract)
    await insertEncryptedRows(sql, v3.middleware, V3_TABLE, [
      {
        id: 'v3-row',
        cells: {
          email: {
            codecId: TEXT_SEARCH,
            value: EncryptedString.from(V3_EMAIL),
          },
        },
      },
    ])

    // v2 half — only when the database carries the EQL v2 composite type.
    const [probe] = await sql<{ present: boolean }[]>`
      SELECT to_regtype(${EQL_V2_ENCRYPTED_TYPE}) IS NOT NULL AS present
    `
    hasEqlV2 = probe?.present === true
    if (!hasEqlV2) return

    await sql.unsafe(`DROP TABLE IF EXISTS "${V2_TABLE}"`)
    await sql.unsafe(
      `CREATE TABLE "${V2_TABLE}" (id text PRIMARY KEY, email ${EQL_V2_ENCRYPTED_TYPE})`,
    )
    v2 = await cipherstashFromStackV2({ contractJson: v2Contract })
    v2Sdk = createCipherstashSdk(
      v2.encryptionClient,
      deriveStackSchemas(v2Contract),
    )
    const v2Middleware = v2.middleware[0]
    if (!v2Middleware)
      throw new Error('cipherstashFromStackV2 returned no middleware')
    await insertEncryptedRows(sql, v2Middleware, V2_TABLE, [
      {
        id: 'v2-row',
        cells: {
          email: {
            codecId: CIPHERSTASH_STRING_CODEC_ID,
            value: EncryptedString.from(V2_EMAIL),
          },
        },
      },
    ])
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  it('the two runtime descriptors share the pack id but carry distinct versions', () => {
    // Both descriptors present the PACK id ('cipherstash') — the
    // runtime matches contract extensionPacks by descriptor id, and one
    // control descriptor emits both generations' contracts. Generation
    // identity lives in the version.
    expect(v3.cs.extensions[0]?.id).toBe(CIPHERSTASH_SPACE_ID)
    expect(v3.cs.extensions[0]?.version).toBe(CIPHERSTASH_V3_EXTENSION_VERSION)
    if (v2) {
      expect(v2.extensions[0]?.id).toBe(CIPHERSTASH_SPACE_ID)
      expect(v2.extensions[0]?.version).not.toBe(v3.cs.extensions[0]?.version)
    }
  })

  it('the v3 client round-trips and queries with the v2 client alive in-process', async () => {
    const result = await runLoweredSelect(
      sql,
      v3.middleware,
      v3Contract,
      selectIdsWhere(
        V3_TABLE,
        callOperator(
          getOperator('eqlEq'),
          columnAccessorV3(V3_TABLE, 'email', TEXT_SEARCH),
          V3_EMAIL,
        ),
      ),
    )
    expect(result.ids).toEqual(['v3-row'])

    const rows = (await sql.unsafe(
      `SELECT email FROM "${V3_TABLE}" WHERE id = 'v3-row'`,
    )) as unknown as Array<{ email: unknown }>
    const decrypted = await decryptCell(v3.sdk, EncryptedString, {
      cell: rows[0]?.email,
      table: V3_TABLE,
      column: 'email',
    })
    expect(decrypted).toBe(V3_EMAIL)
  }, 60_000)

  it('the two wires are physically distinct: v2 composite literal vs v3 JSONB document', async (ctx) => {
    if (!hasEqlV2) return ctx.skip()
    const [v2Row] = (await sql.unsafe(
      `SELECT email::text AS wire FROM "${V2_TABLE}" WHERE id = 'v2-row'`,
    )) as unknown as Array<{ wire: string }>
    expect(v2Row?.wire.startsWith('(')).toBe(true)

    const [v3Row] = (await sql.unsafe(
      `SELECT email::text AS wire FROM "${V3_TABLE}" WHERE id = 'v3-row'`,
    )) as unknown as Array<{ wire: string }>
    expect(v3Row?.wire.trimStart().startsWith('{')).toBe(true)
  }, 60_000)

  it('the v2 client round-trips through its own registry and wire', async (ctx) => {
    if (!hasEqlV2 || !v2Sdk) return ctx.skip()
    // `eql_v2_encrypted` is a composite `(data jsonb)`; project the
    // jsonb field so the driver hands back the EQL payload document.
    const [row] = (await sql.unsafe(
      `SELECT (email).data AS payload FROM "${V2_TABLE}" WHERE id = 'v2-row'`,
    )) as unknown as Array<{ payload: unknown }>
    expect(row?.payload).toBeTypeOf('object')

    const decrypted = await EncryptedString.fromInternal({
      ciphertext: row?.payload,
      table: V2_TABLE,
      column: 'email',
      sdk: v2Sdk,
    }).decrypt()
    expect(decrypted).toBe(V2_EMAIL)
  }, 60_000)
})
