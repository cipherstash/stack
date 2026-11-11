import { expect, test } from 'vitest'
import {
  postgresFreshWriteCheck,
  postgresMigrationChecks,
  validatePostgresBaseline,
} from '../run/postgres-oracle.mjs'

const types = {
  email_v3: 'eql_v3_text_eq',
  age_v3: 'eql_v3_integer_eq',
  notes_v3: 'eql_v3_text',
}
function baseline() {
  function payload(pk: string, column: string) {
    return {
      v: 2,
      k: 'ct',
      i: { t: 'customers', c: column },
      c: `${pk}-${column}-ciphertext`,
      hm: column === 'notes' ? null : `${pk}-${column}-term`,
      ob: null,
      bf: null,
    }
  }
  return {
    rows: ['ada', 'alan', 'grace'].map((pk) => ({
      pk,
      email: payload(pk, 'email'),
      age: payload(pk, 'age'),
      notes: payload(pk, 'notes'),
    })),
    columns: {
      pk: 'text',
      email: 'eql_v2_encrypted',
      age: 'eql_v2_encrypted',
      notes: 'eql_v2_encrypted',
    },
    indexes: [],
  }
}
function migrated() {
  const source = baseline()
  function convert(
    value: ReturnType<typeof baseline>['rows'][number]['email'],
    equality: boolean,
  ) {
    return {
      v: 3,
      i: value.i,
      c: value.c,
      ...(equality ? { hm: value.hm } : {}),
    }
  }
  return {
    ...source,
    columns: { ...source.columns, ...types },
    rows: source.rows.map((row) => ({
      ...row,
      email_v3: convert(row.email, true),
      age_v3: convert(row.age, true),
      notes_v3: convert(row.notes, false),
    })),
    indexes: ['email', 'age'].map((column) => ({
      expression: `eql_v3.eq_term(${column}_v3)`,
      valid: true,
      ready: true,
      partial: false,
      method: 'btree',
    })),
  }
}
test('Postgres oracle permits the proven envelope conversion while preserving source and retained bytes', () => {
  expect(() => validatePostgresBaseline(baseline())).not.toThrow()
  expect(
    postgresMigrationChecks(baseline(), migrated()).every(
      (check) => check.passed,
    ),
  ).toBe(true)
})
test('Postgres no-op fails generation and index checks despite preserving bytes', () => {
  const checks = postgresMigrationChecks(baseline(), baseline())
  expect(checks).toContainEqual(
    expect.objectContaining({
      id: 'migration.postgres-v3-columns',
      passed: false,
    }),
  )
  expect(checks).toContainEqual(
    expect.objectContaining({
      id: 'migration.postgres-indexes',
      passed: false,
    }),
  )
})
test('Postgres oracle identifies row loss independently of byte retention', () => {
  const after = migrated()
  after.rows.pop()
  expect(postgresMigrationChecks(baseline(), after)).toContainEqual(
    expect.objectContaining({
      id: 'behaviour.postgres-row-retention',
      passed: false,
    }),
  )
})
test.each(['c', 'hm'] as const)(
  'Postgres oracle rejects a changed target %s without exporting encrypted values',
  (attribute) => {
    const after = migrated()
    Object.assign(after.rows[0].email_v3, {
      [attribute]: 'sensitive-changed-value',
    })
    const check = postgresMigrationChecks(baseline(), after).find(
      (check) => check.id === 'no-rewrite.postgres-retained-bytes',
    )
    expect(check?.passed).toBe(false)
    expect(check?.cause).toContain('ada/email_v3')
    expect(JSON.stringify(check)).not.toContain('sensitive-changed-value')
  },
)
test('Postgres oracle refuses changed source data even when target data is retained', () => {
  const after = migrated()
  Object.assign(after.rows[0].email, { c: 'rewritten-source' })
  expect(postgresMigrationChecks(baseline(), after)).toContainEqual(
    expect.objectContaining({
      id: 'no-rewrite.postgres-retained-bytes',
      passed: false,
    }),
  )
})

test.each([null, 'malformed', 42, []])(
  'Postgres oracle reports named failures for malformed migrated payloads',
  (payload) => {
    const after = migrated()
    const invalid = {
      ...after,
      rows: after.rows.map((row, index) =>
        index === 0 ? { ...row, email_v3: payload } : row,
      ),
    }
    const checks = postgresMigrationChecks(baseline(), invalid)
    expect(checks).toContainEqual(
      expect.objectContaining({
        id: 'no-rewrite.postgres-retained-bytes',
        passed: false,
      }),
    )
    expect(checks).toContainEqual(
      expect.objectContaining({
        id: 'migration.postgres-v3-columns',
        passed: false,
      }),
    )
  },
)
test('Postgres oracle rejects incorrect target domains and payload mappings', () => {
  const after = migrated()
  after.columns.age_v3 = 'eql_v3_text_eq'
  Object.assign(after.rows[0].email_v3, { i: { t: 'customers', c: 'age' } })
  expect(postgresMigrationChecks(baseline(), after)).toContainEqual(
    expect.objectContaining({
      id: 'migration.postgres-v3-columns',
      passed: false,
    }),
  )
})
test.each(['missing', 'invalid', 'partial', 'wrong-expression'])(
  'Postgres oracle rejects %s indexes',
  (kind) => {
    const after = migrated()
    if (kind === 'missing') after.indexes.pop()
    if (kind === 'invalid') after.indexes[0].valid = false
    if (kind === 'partial') after.indexes[0].partial = true
    if (kind === 'wrong-expression') after.indexes[0].expression = 'email_v3'
    expect(postgresMigrationChecks(baseline(), after)).toContainEqual(
      expect.objectContaining({
        id: 'migration.postgres-indexes',
        passed: false,
      }),
    )
  },
)
test.each([
  null,
  {},
  { ...baseline(), rows: [] },
  { ...baseline(), rows: [{ pk: 'ada' }] },
])('Postgres baseline rejects missing legacy evidence', (snapshot) => {
  expect(() => validatePostgresBaseline(snapshot)).toThrow()
})

test('retained source envelopes remain identical, including identity and unknown metadata', () => {
  for (const change of [
    { i: { t: 'other', c: 'email' } },
    { v: 3 },
    { extra: 'private-value' },
  ]) {
    const after = migrated()
    Object.assign(after.rows[0].email, change)
    const checks = postgresMigrationChecks(baseline(), after)
    expect(checks).toContainEqual(
      expect.objectContaining({
        id: 'no-rewrite.postgres-retained-bytes',
        passed: false,
      }),
    )
    expect(JSON.stringify(checks)).not.toContain('private-value')
  }
})

test('target envelopes reject legacy fields and storage-only hm even when null', () => {
  for (const change of [
    { k: 'ct' },
    { ob: null },
    { bf: null },
    { hm: null },
    { extra: 'private-value' },
  ]) {
    const after = migrated()
    Object.assign(after.rows[0].notes_v3, change)
    expect(postgresMigrationChecks(baseline(), after)).toContainEqual(
      expect.objectContaining({
        id: 'migration.postgres-v3-columns',
        passed: false,
      }),
    )
  }
})

test.each(['duplicate', 'empty'])(
  'invalid migrated %s identities produce named failure evidence',
  (kind) => {
    const after = migrated()
    if (kind === 'duplicate') after.rows.push(after.rows[0])
    else after.rows[0].pk = ''
    expect(postgresMigrationChecks(baseline(), after)).toContainEqual(
      expect.objectContaining({
        id: 'behaviour.postgres-row-retention',
        passed: false,
      }),
    )
  },
)

test('baseline rejects unsupported term fields before migration', () => {
  const before = baseline()
  Object.assign(before.rows[0].email, { sv: 'unsupported' })
  expect(() => validatePostgresBaseline(before)).toThrow(
    'Invalid legacy PostgreSQL payload',
  )
})

test('fresh storage requires all v3 envelopes and null legacy sources', () => {
  const after = migrated()
  const fresh = {
    ...after.rows[0],
    pk: 'new',
    email: null,
    age: null,
    notes: null,
  }
  const snapshot = { ...after, rows: [...after.rows, fresh] }
  expect(postgresFreshWriteCheck(snapshot, 'new').passed).toBe(true)
  for (const column of ['email', 'age', 'notes']) {
    expect(
      postgresFreshWriteCheck(
        {
          ...snapshot,
          rows: [...after.rows, { ...fresh, [column]: after.rows[0].email }],
        },
        'new',
      ).passed,
    ).toBe(false)
    expect(
      postgresFreshWriteCheck(
        {
          ...snapshot,
          rows: [...after.rows, { ...fresh, [`${column}_v3`]: null }],
        },
        'new',
      ).passed,
    ).toBe(false)
  }
})
