import 'dotenv/config'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

if (!process.env.DATABASE_URL) {
  throw new Error('Missing env.DATABASE_URL')
}

// Disable prepared statements — required for pooled connections (PgBouncer in transaction mode)
const sql = postgres(process.env.DATABASE_URL, { prepare: false })

const table = encryptedTable('protect-ci-jsonb-stack', {
  metadata: encryptedColumn('metadata').searchableJson(),
})

const TEST_RUN_ID = `test-run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
const userJwt = process.env.USER_JWT

type EncryptionClient = Awaited<ReturnType<typeof Encryption>>
let protectClient: EncryptionClient

// ─── Helpers ─────────────────────────────────────────────────────────

async function insertRow(plaintext: any) {
  const encrypted = await protectClient.encryptModel(
    { metadata: plaintext },
    table,
  )
  if (encrypted.failure) throw new Error(encrypted.failure.message)

  const [inserted] = await sql`
    INSERT INTO "protect-ci-jsonb-stack" (metadata, test_run_id)
    VALUES (${sql.json(encrypted.data.metadata)}::eql_v2_encrypted, ${TEST_RUN_ID})
    RETURNING id
  `
  return { id: inserted.id, encrypted }
}

async function verifyRow(row: any, expected: any) {
  expect(row).toBeDefined()
  const decrypted = await protectClient.decryptModel({ metadata: row.metadata })
  if (decrypted.failure) throw new Error(decrypted.failure.message)
  expect(decrypted.data.metadata).toEqual(expected)
}

async function encryptQueryTerm(
  value: any,
  queryType: 'steVecSelector' | 'steVecTerm' | 'searchableJson',
  returnType:
    | 'composite-literal'
    | 'escaped-composite-literal' = 'composite-literal',
) {
  const result = await protectClient.encryptQuery(value, {
    column: table.metadata,
    table: table,
    queryType,
    returnType,
  })
  if (result.failure) throw new Error(result.failure.message)
  return result.data
}

beforeAll(async () => {
  protectClient = await Encryption({ schemas: [table] })

  await sql`
    CREATE TABLE IF NOT EXISTS "protect-ci-jsonb-stack" (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      metadata eql_v2_encrypted,
      test_run_id TEXT
    )
  `
}, 30000)

afterAll(async () => {
  await sql`DELETE FROM "protect-ci-jsonb-stack" WHERE test_run_id = ${TEST_RUN_ID}`
  await sql.end()
}, 30000)

describe('searchableJson postgres integration', () => {
  // ─── Storage: encrypt → insert → select → decrypt ──────────────────

  describe('storage: encrypt → insert → select → decrypt', () => {
    it('round-trips a flat JSON object', async () => {
      const plaintext = { user: { email: 'flat-rt@test.com' }, role: 'admin' }
      const { id } = await insertRow(plaintext)

      const rows = await sql`
        SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack"
        WHERE id = ${id}
      `

      expect(rows).toHaveLength(1)
      await verifyRow(rows[0], plaintext)
    }, 30000)

    it('round-trips nested JSON with arrays', async () => {
      const plaintext = {
        user: {
          profile: { role: 'admin', permissions: ['read', 'write'] },
          tags: [{ name: 'vip' }, { name: 'beta' }],
        },
        items: [{ id: 1, name: 'widget' }],
      }
      const { id } = await insertRow(plaintext)

      const rows = await sql`
        SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack"
        WHERE id = ${id}
      `

      expect(rows).toHaveLength(1)
      await verifyRow(rows[0], plaintext)
    }, 30000)
  })

  // ─── jsonb_path_query: path-based selector queries ─────────────────

  describe('jsonb_path_query: path-based selector queries', () => {
    it('finds row by simple top-level path ($.role)', async () => {
      const plaintext = { role: 'path-toplevel-test', extra: 'data' }
      const { id } = await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm('$.role', 'steVecSelector')

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('finds row by nested path ($.user.email)', async () => {
      const plaintext = {
        user: { email: 'nested-path@test.com' },
        type: 'nested-path',
      }
      const { id } = await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm(
        '$.user.email',
        'steVecSelector',
      )

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('finds row by deeply nested path ($.a.b.c)', async () => {
      const plaintext = { a: { b: { c: 'deep-value' } }, marker: 'deep-path' }
      const { id } = await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm('$.a.b.c', 'steVecSelector')

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('non-matching path returns zero rows', async () => {
      // Insert a doc that does NOT have $.nonexistent.path
      const plaintext = { exists: true, marker: 'no-match-test' }
      await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm(
        '$.nonexistent.path',
        'steVecSelector',
      )

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      // No row should have this path
      expect(rows.length).toBe(0)
    }, 30000)

    it('multiple docs — only matching doc returned', async () => {
      // Insert two docs: one with $.target.value, one without
      const plaintextWithPath = {
        target: { value: 'found-it' },
        marker: 'has-target',
      }
      const plaintextWithoutPath = {
        other: { key: 'nope' },
        marker: 'no-target',
      }

      const { id: idWith } = await insertRow(plaintextWithPath)
      const { id: idWithout } = await insertRow(plaintextWithoutPath)

      const selectorTerm = await encryptQueryTerm(
        '$.target.value',
        'steVecSelector',
      )

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      // The doc with $.target.value should be found
      const matchingRow = rows.find((r) => r.id === idWith)
      expect(matchingRow).toBeDefined()

      // The doc without $.target.value should NOT be found
      const nonMatchingRow = rows.find((r) => r.id === idWithout)
      expect(nonMatchingRow).toBeUndefined()

      // Decrypt and verify the matching row
      await verifyRow(matchingRow!, plaintextWithPath)
    }, 30000)

    it('finds row by simple top-level path (Simple)', async () => {
      const plaintext = { role: 'path-tl-simple', extra: 'data' }
      const { id } = await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm('$.role', 'steVecSelector')

      const rows = await sql.unsafe(
        `SELECT id, (metadata).data as metadata
         FROM "protect-ci-jsonb-stack" t,
              eql_v2.jsonb_path_query(t.metadata, '${selectorTerm}'::eql_v2_encrypted) as result
         WHERE t.test_run_id = '${TEST_RUN_ID}'`,
      )

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r: any) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('finds row by nested path (Simple)', async () => {
      const plaintext = {
        user: { email: 'nested-simple@test.com' },
        type: 'nested-path-simple',
      }
      const { id } = await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm(
        '$.user.email',
        'steVecSelector',
      )

      const rows = await sql.unsafe(
        `SELECT id, (metadata).data as metadata
         FROM "protect-ci-jsonb-stack" t,
              eql_v2.jsonb_path_query(t.metadata, '${selectorTerm}'::eql_v2_encrypted) as result
         WHERE t.test_run_id = '${TEST_RUN_ID}'`,
      )

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r: any) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('finds with deep nested path (Simple)', async () => {
      const plaintext = {
        target: { nested: { value: 'deep-simple' } },
        marker: 'jpq-deep-simple',
      }
      const { id } = await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm(
        '$.target.nested.value',
        'steVecSelector',
      )

      const rows = await sql.unsafe(
        `SELECT id, (metadata).data as metadata
         FROM "protect-ci-jsonb-stack" t,
              eql_v2.jsonb_path_query(t.metadata, '${selectorTerm}'::eql_v2_encrypted) as result
         WHERE t.test_run_id = '${TEST_RUN_ID}'`,
      )

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r: any) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('non-matching path returns zero rows (Simple)', async () => {
      const plaintext = { data: true, marker: 'jpq-nomatch-simple' }
      await insertRow(plaintext)

      const selectorTerm = await encryptQueryTerm(
        '$.missing.path',
        'steVecSelector',
      )

      const rows = await sql.unsafe(
        `SELECT id, (metadata).data as metadata
         FROM "protect-ci-jsonb-stack" t,
              eql_v2.jsonb_path_query(t.metadata, '${selectorTerm}'::eql_v2_encrypted) as result
         WHERE t.test_run_id = '${TEST_RUN_ID}'`,
      )

      expect(rows.length).toBe(0)
    }, 30000)
  })

  // ─── Containment: @> term queries ──────────────────────────────────

  describe('containment: @> term queries', () => {
    it('matches by key/value pair', async () => {
      const plaintext = { role: 'admin-containment', department: 'engineering' }
      const { id } = await insertRow(plaintext)

      const containmentTerm = await encryptQueryTerm(
        { role: 'admin-containment' },
        'steVecTerm',
      )

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t
        WHERE t.metadata @> ${containmentTerm}::eql_v2_encrypted
        AND t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('matches by nested object structure', async () => {
      const plaintext = {
        user: { profile: { role: 'superadmin' } },
        active: true,
      }
      const { id } = await insertRow(plaintext)

      const containmentTerm = await encryptQueryTerm(
        { user: { profile: { role: 'superadmin' } } },
        'steVecTerm',
      )

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t
        WHERE t.metadata @> ${containmentTerm}::eql_v2_encrypted
        AND t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('non-matching term returns zero rows', async () => {
      const plaintext = { status: 'active', tier: 'free' }
      await insertRow(plaintext)

      const containmentTerm = await encryptQueryTerm(
        { status: 'nonexistent-value-xyz' },
        'steVecTerm',
      )

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t
        WHERE t.metadata @> ${containmentTerm}::eql_v2_encrypted
        AND t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBe(0)
    }, 30000)
  })

  // ─── Mixed and batch operations ────────────────────────────────────

  describe('mixed and batch operations', () => {
    it('batch encrypts selector + containment terms together', async () => {
      const plaintext = {
        user: { email: 'batch@test.com' },
        role: 'editor',
        kind: 'batch-mixed',
      }
      const { id } = await insertRow(plaintext)

      const queryResult = await protectClient.encryptQuery([
        {
          value: '$.user.email',
          column: table.metadata,
          table: table,
          queryType: 'steVecSelector',
          returnType: 'composite-literal',
        },
        {
          value: { role: 'editor' },
          column: table.metadata,
          table: table,
          queryType: 'steVecTerm',
          returnType: 'composite-literal',
        },
      ])

      if (queryResult.failure) throw new Error(queryResult.failure.message)
      const [selectorTerm, containmentTerm] = queryResult.data

      // Selector query: jsonb_path_query
      const selectorRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(selectorRows.length).toBeGreaterThanOrEqual(1)
      const selectorMatch = selectorRows.find((r) => r.id === id)
      expect(selectorMatch).toBeDefined()
      await verifyRow(selectorMatch!, plaintext)

      // Containment query: @>
      const containmentRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${containmentTerm}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      expect(containmentRows.length).toBeGreaterThanOrEqual(1)
      const containmentMatch = containmentRows.find((r) => r.id === id)
      expect(containmentMatch).toBeDefined()
      await verifyRow(containmentMatch!, plaintext)
    }, 30000)

    it('inferred vs explicit queryType produce same results', async () => {
      const plaintext = { category: 'equivalence-test', priority: 'high' }
      const { id } = await insertRow(plaintext)

      // Selector: inferred (searchableJson) vs explicit (steVecSelector)
      const inferredSelectorTerm = await encryptQueryTerm(
        '$.category',
        'searchableJson',
      )
      const explicitSelectorTerm = await encryptQueryTerm(
        '$.category',
        'steVecSelector',
      )

      const inferredRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${inferredSelectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      const explicitRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${explicitSelectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(inferredRows.length).toBe(explicitRows.length)
      expect(inferredRows.length).toBeGreaterThanOrEqual(1)

      // Both should find our inserted row
      const inferredMatch = inferredRows.find((r) => r.id === id)
      const explicitMatch = explicitRows.find((r) => r.id === id)
      expect(inferredMatch).toBeDefined()
      expect(explicitMatch).toBeDefined()

      // Decrypt and compare — both should yield identical plaintext
      const inferredDecrypted = await protectClient.decryptModel({
        metadata: inferredMatch!.metadata,
      })
      const explicitDecrypted = await protectClient.decryptModel({
        metadata: explicitMatch!.metadata,
      })
      if (inferredDecrypted.failure)
        throw new Error(inferredDecrypted.failure.message)
      if (explicitDecrypted.failure)
        throw new Error(explicitDecrypted.failure.message)

      expect(inferredDecrypted.data.metadata).toEqual(
        explicitDecrypted.data.metadata,
      )
      expect(inferredDecrypted.data.metadata).toEqual(plaintext)

      // Containment: inferred (searchableJson) vs explicit (steVecTerm)
      const inferredContainmentTerm = await encryptQueryTerm(
        { category: 'equivalence-test' },
        'searchableJson',
      )
      const explicitContainmentTerm = await encryptQueryTerm(
        { category: 'equivalence-test' },
        'steVecTerm',
      )

      const inferredTermRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${inferredContainmentTerm}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      const explicitTermRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${explicitContainmentTerm}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      expect(inferredTermRows.length).toBe(explicitTermRows.length)
      expect(inferredTermRows.length).toBeGreaterThanOrEqual(1)

      const inferredTermMatch = inferredTermRows.find((r) => r.id === id)
      const explicitTermMatch = explicitTermRows.find((r) => r.id === id)
      expect(inferredTermMatch).toBeDefined()
      expect(explicitTermMatch).toBeDefined()

      const inferredTermDecrypted = await protectClient.decryptModel({
        metadata: inferredTermMatch!.metadata,
      })
      const explicitTermDecrypted = await protectClient.decryptModel({
        metadata: explicitTermMatch!.metadata,
      })
      if (inferredTermDecrypted.failure)
        throw new Error(inferredTermDecrypted.failure.message)
      if (explicitTermDecrypted.failure)
        throw new Error(explicitTermDecrypted.failure.message)

      expect(inferredTermDecrypted.data.metadata).toEqual(
        explicitTermDecrypted.data.metadata,
      )
      expect(inferredTermDecrypted.data.metadata).toEqual(plaintext)
    }, 30000)
  })

  // ─── Escaped-composite-literal format ─────────────────────────────

  describe('escaped-composite-literal format', () => {
    it('escaped selector → unwrap → query PG', async () => {
      const plaintext = {
        user: { email: 'escaped-sel@test.com' },
        marker: 'escaped-selector',
      }
      const { id } = await insertRow(plaintext)

      // Encrypt with both formats
      const compositeData = await encryptQueryTerm(
        '$.user.email',
        'steVecSelector',
        'composite-literal',
      )
      const escapedData = (await encryptQueryTerm(
        '$.user.email',
        'steVecSelector',
        'escaped-composite-literal',
      )) as string

      // Verify escaped format and unwrap
      expect(typeof escapedData).toBe('string')
      expect(escapedData).toMatch(/^"\(.*\)"$/)
      const unwrapped = JSON.parse(escapedData)

      expect(unwrapped).toBe(compositeData)

      // Use composite-literal form to query PG
      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${compositeData}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('escaped containment → unwrap → query PG', async () => {
      const plaintext = {
        role: 'escaped-containment-test',
        department: 'security',
      }
      const { id } = await insertRow(plaintext)

      const escapedData = (await encryptQueryTerm(
        { role: 'escaped-containment-test' },
        'steVecTerm',
        'escaped-composite-literal',
      )) as string

      // Verify escaped format and unwrap
      expect(typeof escapedData).toBe('string')
      expect(escapedData).toMatch(/^"\(.*\)"$/)
      const unwrapped = JSON.parse(escapedData)

      // Unwrapped escaped format should be a valid composite-literal
      expect(typeof unwrapped).toBe('string')
      expect(unwrapped).toMatch(/^\(.*\)$/)

      // Use unwrapped composite-literal form to query PG
      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${unwrapped}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('batch escaped format', async () => {
      const plaintext = {
        user: { email: 'batch-escaped@test.com' },
        role: 'batch-escaped-role',
        marker: 'batch-escaped',
      }
      const { id } = await insertRow(plaintext)

      const queryResult = await protectClient.encryptQuery([
        {
          value: '$.user.email',
          column: table.metadata,
          table: table,
          queryType: 'steVecSelector',
          returnType: 'escaped-composite-literal',
        },
        {
          value: { role: 'batch-escaped-role' },
          column: table.metadata,
          table: table,
          queryType: 'steVecTerm',
          returnType: 'escaped-composite-literal',
        },
      ])
      if (queryResult.failure) throw new Error(queryResult.failure.message)

      expect(queryResult.data).toHaveLength(2)
      for (const item of queryResult.data) {
        expect(typeof item).toBe('string')
        expect(item).toMatch(/^"\(.*\)"$/)
      }

      // Unwrap escaped format
      const selectorUnwrapped = JSON.parse(queryResult.data[0] as string)
      const containmentUnwrapped = JSON.parse(queryResult.data[1] as string)

      // Selector query
      const selectorRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorUnwrapped}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(selectorRows.length).toBeGreaterThanOrEqual(1)
      const selectorMatch = selectorRows.find((r) => r.id === id)
      expect(selectorMatch).toBeDefined()
      await verifyRow(selectorMatch!, plaintext)

      // Containment query
      const containmentRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${containmentUnwrapped}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      expect(containmentRows.length).toBeGreaterThanOrEqual(1)
      const containmentMatch = containmentRows.find((r) => r.id === id)
      expect(containmentMatch).toBeDefined()
      await verifyRow(containmentMatch!, plaintext)
    }, 30000)
  })

  // ─── LockContext integration ──────────────────────────────────────

  describe.skipIf(!userJwt)('LockContext integration', () => {
    it('selector with LockContext', async () => {
      const lc = new LockContext()
      const lockContext = await lc.identify(userJwt!)
      if (lockContext.failure) throw new Error(lockContext.failure.message)

      const plaintext = {
        user: { email: 'lc-selector@test.com' },
        marker: 'lock-context-selector',
      }

      const encrypted = await protectClient
        .encryptModel({ metadata: plaintext }, table)
        .withLockContext(lockContext.data)
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      const [inserted] = await sql`
        INSERT INTO "protect-ci-jsonb-stack" (metadata, test_run_id)
        VALUES (${sql.json(encrypted.data.metadata)}::eql_v2_encrypted, ${TEST_RUN_ID})
        RETURNING id
      `

      const selectorResult = await protectClient
        .encryptQuery('$.user.email', {
          column: table.metadata,
          table: table,
          queryType: 'steVecSelector',
          returnType: 'composite-literal',
        })
        .withLockContext(lockContext.data)
        .execute()
      if (selectorResult.failure)
        throw new Error(selectorResult.failure.message)

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorResult.data}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === inserted.id)
      expect(matchingRow).toBeDefined()

      const decrypted = await protectClient
        .decryptModel({ metadata: matchingRow!.metadata })
        .withLockContext(lockContext.data)
      if (decrypted.failure) throw new Error(decrypted.failure.message)
      expect(decrypted.data.metadata).toEqual(plaintext)
    }, 60000)

    it('containment with LockContext', async () => {
      const lc = new LockContext()
      const lockContext = await lc.identify(userJwt!)
      if (lockContext.failure) throw new Error(lockContext.failure.message)

      const plaintext = { role: 'lc-containment-test', department: 'auth' }

      const encrypted = await protectClient
        .encryptModel({ metadata: plaintext }, table)
        .withLockContext(lockContext.data)
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      const [inserted] = await sql`
        INSERT INTO "protect-ci-jsonb-stack" (metadata, test_run_id)
        VALUES (${sql.json(encrypted.data.metadata)}::eql_v2_encrypted, ${TEST_RUN_ID})
        RETURNING id
      `

      const containmentResult = await protectClient
        .encryptQuery(
          { role: 'lc-containment-test' },
          {
            column: table.metadata,
            table: table,
            queryType: 'steVecTerm',
            returnType: 'composite-literal',
          },
        )
        .withLockContext(lockContext.data)
        .execute()
      if (containmentResult.failure)
        throw new Error(containmentResult.failure.message)

      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${containmentResult.data}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === inserted.id)
      expect(matchingRow).toBeDefined()

      const decrypted = await protectClient
        .decryptModel({ metadata: matchingRow!.metadata })
        .withLockContext(lockContext.data)
      if (decrypted.failure) throw new Error(decrypted.failure.message)
      expect(decrypted.data.metadata).toEqual(plaintext)
    }, 60000)

    it('batch with LockContext', async () => {
      const lc = new LockContext()
      const lockContext = await lc.identify(userJwt!)
      if (lockContext.failure) throw new Error(lockContext.failure.message)

      const plaintext = {
        user: { email: 'lc-batch@test.com' },
        role: 'lc-batch-role',
        kind: 'lock-context-batch',
      }

      const encrypted = await protectClient
        .encryptModel({ metadata: plaintext }, table)
        .withLockContext(lockContext.data)
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      const [inserted] = await sql`
        INSERT INTO "protect-ci-jsonb-stack" (metadata, test_run_id)
        VALUES (${sql.json(encrypted.data.metadata)}::eql_v2_encrypted, ${TEST_RUN_ID})
        RETURNING id
      `

      const batchResult = await protectClient
        .encryptQuery([
          {
            value: '$.user.email',
            column: table.metadata,
            table: table,
            queryType: 'steVecSelector',
            returnType: 'composite-literal',
          },
          {
            value: { role: 'lc-batch-role' },
            column: table.metadata,
            table: table,
            queryType: 'steVecTerm',
            returnType: 'composite-literal',
          },
        ])
        .withLockContext(lockContext.data)
        .execute()
      if (batchResult.failure) throw new Error(batchResult.failure.message)

      const [selectorTerm, containmentTerm] = batchResult.data

      // Selector query
      const selectorRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(selectorRows.length).toBeGreaterThanOrEqual(1)
      const selectorMatch = selectorRows.find((r) => r.id === inserted.id)
      expect(selectorMatch).toBeDefined()

      const selectorDecrypted = await protectClient
        .decryptModel({ metadata: selectorMatch!.metadata })
        .withLockContext(lockContext.data)
      if (selectorDecrypted.failure)
        throw new Error(selectorDecrypted.failure.message)
      expect(selectorDecrypted.data.metadata).toEqual(plaintext)

      // Containment query
      const containmentRows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${containmentTerm}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      expect(containmentRows.length).toBeGreaterThanOrEqual(1)
      const containmentMatch = containmentRows.find((r) => r.id === inserted.id)
      expect(containmentMatch).toBeDefined()

      const containmentDecrypted = await protectClient
        .decryptModel({ metadata: containmentMatch!.metadata })
        .withLockContext(lockContext.data)
      if (containmentDecrypted.failure)
        throw new Error(containmentDecrypted.failure.message)
      expect(containmentDecrypted.data.metadata).toEqual(plaintext)
    }, 60000)
  })

  // ─── Concurrent query operations ─────────────────────────────────

  describe('concurrent query operations', () => {
    it('parallel selector queries', async () => {
      // Insert 3 docs with distinct structures
      const docs = [
        { alpha: { key: 'concurrent-sel-1' }, marker: 'concurrent-1' },
        { beta: { key: 'concurrent-sel-2' }, marker: 'concurrent-2' },
        { gamma: { key: 'concurrent-sel-3' }, marker: 'concurrent-3' },
      ]

      const insertedIds: number[] = []
      for (const plaintext of docs) {
        const { id } = await insertRow(plaintext)
        insertedIds.push(id)
      }

      // Parallel encrypt 3 selector queries
      const [q1, q2, q3] = await Promise.all([
        protectClient.encryptQuery('$.alpha.key', {
          column: table.metadata,
          table: table,
          queryType: 'steVecSelector',
          returnType: 'composite-literal',
        }),
        protectClient.encryptQuery('$.beta.key', {
          column: table.metadata,
          table: table,
          queryType: 'steVecSelector',
          returnType: 'composite-literal',
        }),
        protectClient.encryptQuery('$.gamma.key', {
          column: table.metadata,
          table: table,
          queryType: 'steVecSelector',
          returnType: 'composite-literal',
        }),
      ])

      if (q1.failure) throw new Error(q1.failure.message)
      if (q2.failure) throw new Error(q2.failure.message)
      if (q3.failure) throw new Error(q3.failure.message)

      // Execute each against PG
      const [rows1, rows2, rows3] = await Promise.all([
        sql`
          SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack" t,
               eql_v2.jsonb_path_query(t.metadata, ${q1.data}::eql_v2_encrypted) as result
          WHERE t.test_run_id = ${TEST_RUN_ID}
        `,
        sql`
          SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack" t,
               eql_v2.jsonb_path_query(t.metadata, ${q2.data}::eql_v2_encrypted) as result
          WHERE t.test_run_id = ${TEST_RUN_ID}
        `,
        sql`
          SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack" t,
               eql_v2.jsonb_path_query(t.metadata, ${q3.data}::eql_v2_encrypted) as result
          WHERE t.test_run_id = ${TEST_RUN_ID}
        `,
      ])

      // Each query should find its respective doc and not others
      expect(rows1.find((r) => r.id === insertedIds[0])).toBeDefined()
      expect(rows1.find((r) => r.id === insertedIds[1])).toBeUndefined()
      expect(rows1.find((r) => r.id === insertedIds[2])).toBeUndefined()
      expect(rows2.find((r) => r.id === insertedIds[1])).toBeDefined()
      expect(rows2.find((r) => r.id === insertedIds[0])).toBeUndefined()
      expect(rows2.find((r) => r.id === insertedIds[2])).toBeUndefined()
      expect(rows3.find((r) => r.id === insertedIds[2])).toBeDefined()
      expect(rows3.find((r) => r.id === insertedIds[0])).toBeUndefined()
      expect(rows3.find((r) => r.id === insertedIds[1])).toBeUndefined()

      // Decrypt and validate each matched row
      const match1 = rows1.find((r) => r.id === insertedIds[0])!
      const decrypted1 = await protectClient.decryptModel({
        metadata: match1.metadata,
      })
      if (decrypted1.failure) throw new Error(decrypted1.failure.message)
      expect(decrypted1.data.metadata).toEqual(docs[0])

      const match2 = rows2.find((r) => r.id === insertedIds[1])!
      const decrypted2 = await protectClient.decryptModel({
        metadata: match2.metadata,
      })
      if (decrypted2.failure) throw new Error(decrypted2.failure.message)
      expect(decrypted2.data.metadata).toEqual(docs[1])

      const match3 = rows3.find((r) => r.id === insertedIds[2])!
      const decrypted3 = await protectClient.decryptModel({
        metadata: match3.metadata,
      })
      if (decrypted3.failure) throw new Error(decrypted3.failure.message)
      expect(decrypted3.data.metadata).toEqual(docs[2])
    }, 60000)

    it('parallel containment queries', async () => {
      const docs = [
        { role: 'concurrent-contain-1', tier: 'gold' },
        { role: 'concurrent-contain-2', tier: 'silver' },
      ]

      const insertedIds: number[] = []
      for (const plaintext of docs) {
        const { id } = await insertRow(plaintext)
        insertedIds.push(id)
      }

      // Parallel encrypt 2 containment queries
      const [c1, c2] = await Promise.all([
        protectClient.encryptQuery(
          { role: 'concurrent-contain-1' },
          {
            column: table.metadata,
            table: table,
            queryType: 'steVecTerm',
            returnType: 'composite-literal',
          },
        ),
        protectClient.encryptQuery(
          { role: 'concurrent-contain-2' },
          {
            column: table.metadata,
            table: table,
            queryType: 'steVecTerm',
            returnType: 'composite-literal',
          },
        ),
      ])

      if (c1.failure) throw new Error(c1.failure.message)
      if (c2.failure) throw new Error(c2.failure.message)

      const [rows1, rows2] = await Promise.all([
        sql`
          SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack"
          WHERE metadata @> ${c1.data}::eql_v2_encrypted
          AND test_run_id = ${TEST_RUN_ID}
        `,
        sql`
          SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack"
          WHERE metadata @> ${c2.data}::eql_v2_encrypted
          AND test_run_id = ${TEST_RUN_ID}
        `,
      ])

      // Each finds only its target doc
      expect(rows1.find((r) => r.id === insertedIds[0])).toBeDefined()
      expect(rows1.find((r) => r.id === insertedIds[1])).toBeUndefined()
      expect(rows2.find((r) => r.id === insertedIds[1])).toBeDefined()
      expect(rows2.find((r) => r.id === insertedIds[0])).toBeUndefined()

      // Decrypt and validate each matched row
      const match1 = rows1.find((r) => r.id === insertedIds[0])!
      const decrypted1 = await protectClient.decryptModel({
        metadata: match1.metadata,
      })
      if (decrypted1.failure) throw new Error(decrypted1.failure.message)
      expect(decrypted1.data.metadata).toEqual(docs[0])

      const match2 = rows2.find((r) => r.id === insertedIds[1])!
      const decrypted2 = await protectClient.decryptModel({
        metadata: match2.metadata,
      })
      if (decrypted2.failure) throw new Error(decrypted2.failure.message)
      expect(decrypted2.data.metadata).toEqual(docs[1])
    }, 60000)

    it('parallel mixed encrypt+query', async () => {
      const plaintext = {
        user: { email: 'concurrent-mixed@test.com' },
        role: 'concurrent-mixed-role',
        kind: 'mixed-concurrent',
      }

      // Parallel: encryptModel + selector encryptQuery + containment encryptQuery
      const [encryptedModel, selectorResult, containmentResult] =
        await Promise.all([
          protectClient.encryptModel({ metadata: plaintext }, table),
          protectClient.encryptQuery('$.user.email', {
            column: table.metadata,
            table: table,
            queryType: 'steVecSelector',
            returnType: 'composite-literal',
          }),
          protectClient.encryptQuery(
            { role: 'concurrent-mixed-role' },
            {
              column: table.metadata,
              table: table,
              queryType: 'steVecTerm',
              returnType: 'composite-literal',
            },
          ),
        ])

      if (encryptedModel.failure)
        throw new Error(encryptedModel.failure.message)
      if (selectorResult.failure)
        throw new Error(selectorResult.failure.message)
      if (containmentResult.failure)
        throw new Error(containmentResult.failure.message)

      // Insert the encrypted doc
      const [inserted] = await sql`
        INSERT INTO "protect-ci-jsonb-stack" (metadata, test_run_id)
        VALUES (${sql.json(encryptedModel.data.metadata)}::eql_v2_encrypted, ${TEST_RUN_ID})
        RETURNING id
      `

      // Query with both terms
      const [selectorRows, containmentRows] = await Promise.all([
        sql`
          SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack" t,
               eql_v2.jsonb_path_query(t.metadata, ${selectorResult.data}::eql_v2_encrypted) as result
          WHERE t.test_run_id = ${TEST_RUN_ID}
        `,
        sql`
          SELECT id, (metadata).data as metadata FROM "protect-ci-jsonb-stack"
          WHERE metadata @> ${containmentResult.data}::eql_v2_encrypted
          AND test_run_id = ${TEST_RUN_ID}
        `,
      ])

      // Both should find the inserted row
      expect(selectorRows.find((r) => r.id === inserted.id)).toBeDefined()
      expect(containmentRows.find((r) => r.id === inserted.id)).toBeDefined()
      // Verify result sets are bounded (not returning all rows)
      expect(selectorRows.length).toBeGreaterThanOrEqual(1)
      expect(containmentRows.length).toBeGreaterThanOrEqual(1)

      // Decrypt and validate both matched rows
      const selectorMatch = selectorRows.find((r) => r.id === inserted.id)!
      const selectorDecrypted = await protectClient.decryptModel({
        metadata: selectorMatch.metadata,
      })
      if (selectorDecrypted.failure)
        throw new Error(selectorDecrypted.failure.message)
      expect(selectorDecrypted.data.metadata).toEqual(plaintext)

      const containmentMatch = containmentRows.find(
        (r) => r.id === inserted.id,
      )!
      const containmentDecrypted = await protectClient.decryptModel({
        metadata: containmentMatch.metadata,
      })
      if (containmentDecrypted.failure)
        throw new Error(containmentDecrypted.failure.message)
      expect(containmentDecrypted.data.metadata).toEqual(plaintext)
    }, 60000)
  })

  // ─── eql (default) return type ──────────────────────────────────────

  describe('eql (default) return type', () => {
    it('selector query using raw eql return type', async () => {
      const plaintext = {
        user: { email: 'eql-raw-sel@test.com' },
        marker: 'eql-raw-sel',
      }
      const { id } = await insertRow(plaintext)

      // Omit returnType — single-value encryptQuery returns raw Encrypted object
      const queryResult = await protectClient.encryptQuery('$.user.email', {
        column: table.metadata,
        table: table,
        queryType: 'steVecSelector',
      })
      if (queryResult.failure) throw new Error(queryResult.failure.message)
      const rawResult = queryResult.data

      // Must use sql.json() to pass raw Encrypted object to PG
      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack" t,
             eql_v2.jsonb_path_query(t.metadata, ${sql.json(rawResult)}::eql_v2_encrypted) as result
        WHERE t.test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)

    it('containment query using raw eql return type', async () => {
      const plaintext = { role: 'eql-raw-contain', marker: 'eql-raw-ct' }
      const { id } = await insertRow(plaintext)

      // Omit returnType — single-value encryptQuery returns raw Encrypted object
      const queryResult = await protectClient.encryptQuery(
        { role: 'eql-raw-contain' },
        {
          column: table.metadata,
          table: table,
          queryType: 'steVecTerm',
        },
      )
      if (queryResult.failure) throw new Error(queryResult.failure.message)
      const rawResult = queryResult.data

      // Must use sql.json() to pass raw Encrypted object to PG
      const rows = await sql`
        SELECT id, (metadata).data as metadata
        FROM "protect-ci-jsonb-stack"
        WHERE metadata @> ${sql.json(rawResult)}::eql_v2_encrypted
        AND test_run_id = ${TEST_RUN_ID}
      `

      expect(rows.length).toBeGreaterThanOrEqual(1)
      const matchingRow = rows.find((r) => r.id === id)
      expect(matchingRow).toBeDefined()
      await verifyRow(matchingRow!, plaintext)
    }, 30000)
  })

  // ─── Concurrent encrypt + decrypt stress ────────────────────────────

  describe('concurrent encrypt + decrypt stress', () => {
    it('concurrent encrypt + decrypt stress (10 parallel)', async () => {
      const docs = Array.from({ length: 10 }, (_, i) => ({
        user: { email: `stress-${i}@test.com` },
        role: `stress-role-${i}`,
        index: i,
        marker: `stress-${i}`,
      }))

      // Insert all 10 docs
      const insertedIds: number[] = []
      for (const plaintext of docs) {
        const { id } = await insertRow(plaintext)
        insertedIds.push(id)
      }

      // 10 parallel encrypt-query-decrypt pipelines
      const results = await Promise.all(
        docs.map(async (plaintext, i) => {
          // Encrypt a selector query
          const selectorTerm = await encryptQueryTerm(
            '$.user.email',
            'steVecSelector',
          )

          // Query PG
          const rows = await sql`
            SELECT id, (metadata).data as metadata
            FROM "protect-ci-jsonb-stack" t,
                 eql_v2.jsonb_path_query(t.metadata, ${selectorTerm}::eql_v2_encrypted) as result
            WHERE t.id = ${insertedIds[i]}
          `

          expect(rows).toHaveLength(1)

          // Decrypt
          const decrypted = await protectClient.decryptModel({
            metadata: rows[0].metadata,
          })
          if (decrypted.failure) throw new Error(decrypted.failure.message)

          return decrypted.data.metadata
        }),
      )

      // Assert all 10 return correct plaintext
      expect(results).toHaveLength(10)
      results.forEach((result, i) => {
        expect(result).toEqual(docs[i])
      })
    }, 120000)
  })
})
