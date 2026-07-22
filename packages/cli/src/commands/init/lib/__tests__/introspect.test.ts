import { beforeEach, describe, expect, it, vi } from 'vitest'
import * as p from '@clack/prompts'
import {
  candidateDomains,
  defaultDomain,
  pgTypeToDataType,
  selectTableColumns,
} from '../introspect.js'

const selectMock = vi.fn()
const multiselectMock = vi.fn()
// Real clack signals cancellation by returning a unique symbol that `isCancel`
// checks by identity. Model that faithfully with a sentinel so cancellation
// branches are reachable — a hardcoded `isCancel: () => false` would make them
// structurally untestable.
const CANCEL = Symbol('clack.cancel')
vi.mock('@clack/prompts', () => ({
  select: (...args: unknown[]) => selectMock(...args),
  multiselect: (...args: unknown[]) => multiselectMock(...args),
  isCancel: (v: unknown) => v === CANCEL,
  log: { info: vi.fn(), success: vi.fn() },
  spinner: () => ({ start: vi.fn(), stop: vi.fn() }),
}))

describe('pgTypeToDataType', () => {
  it('maps integer/float/numeric udt names to number', () => {
    for (const udt of ['int2', 'int4', 'int8', 'float4', 'float8', 'numeric']) {
      expect(pgTypeToDataType(udt)).toBe('number')
    }
  })

  it('maps bool to boolean, date/timestamp to date, json/jsonb to json', () => {
    expect(pgTypeToDataType('bool')).toBe('boolean')
    expect(pgTypeToDataType('date')).toBe('date')
    expect(pgTypeToDataType('timestamptz')).toBe('date')
    expect(pgTypeToDataType('jsonb')).toBe('json')
  })

  it('falls back to string for unknown udt names', () => {
    expect(pgTypeToDataType('citext')).toBe('string')
  })
})

describe('candidateDomains', () => {
  it('offers the full text ladder for strings', () => {
    const values = candidateDomains('string').map((o) => o.value)
    expect(values).toEqual(['Text', 'TextEq', 'TextOrd', 'TextMatch', 'TextSearch'])
  })

  it('offers the integer ladder for numbers', () => {
    const values = candidateDomains('number').map((o) => o.value)
    expect(values).toEqual(['Integer', 'IntegerEq', 'IntegerOrd'])
  })

  it('offers the date ladder for dates', () => {
    const values = candidateDomains('date').map((o) => o.value)
    expect(values).toEqual(['Date', 'DateEq', 'DateOrd'])
  })

  it('offers a single storage-only domain for boolean and json', () => {
    expect(candidateDomains('boolean').map((o) => o.value)).toEqual(['Boolean'])
    expect(candidateDomains('json').map((o) => o.value)).toEqual(['Json'])
  })

  it('gives every option a label and a hint', () => {
    for (const opt of candidateDomains('string')) {
      expect(opt.label.length).toBeGreaterThan(0)
      expect(opt.hint.length).toBeGreaterThan(0)
    }
  })
})

describe('defaultDomain', () => {
  it('defaults to the widest searchable domain per type', () => {
    expect(defaultDomain('string')).toBe('TextSearch')
    expect(defaultDomain('number')).toBe('IntegerOrd')
    expect(defaultDomain('date')).toBe('DateOrd')
    expect(defaultDomain('boolean')).toBe('Boolean')
    expect(defaultDomain('json')).toBe('Json')
  })

  it('always returns a member of that type candidate set', () => {
    for (const dt of ['string', 'number', 'date', 'boolean', 'json'] as const) {
      const values = candidateDomains(dt).map((o) => o.value)
      expect(values).toContain(defaultDomain(dt))
    }
  })
})

describe('selectTableColumns', () => {
  beforeEach(() => {
    selectMock.mockReset()
    multiselectMock.mockReset()
  })

  const tables = [
    {
      tableName: 'users',
      columns: [
        { columnName: 'email', dataType: 'text', udtName: 'text', isEqlEncrypted: false },
        { columnName: 'age', dataType: 'integer', udtName: 'int4', isEqlEncrypted: false },
        { columnName: 'verified', dataType: 'boolean', udtName: 'bool', isEqlEncrypted: false },
      ],
    },
  ]

  it('assigns the per-column domain chosen at the select prompt', async () => {
    // 1st select: which table. Then one select per multi-domain column.
    selectMock
      .mockResolvedValueOnce('users') // table pick
      .mockResolvedValueOnce('TextEq') // email domain
      .mockResolvedValueOnce('IntegerOrd') // age domain
    // boolean has a single domain → no prompt for it.
    multiselectMock.mockResolvedValueOnce(['email', 'age', 'verified'])

    const schema = await selectTableColumns(tables)

    expect(schema).toEqual({
      tableName: 'users',
      columns: [
        { name: 'email', domain: 'TextEq' },
        { name: 'age', domain: 'IntegerOrd' },
        { name: 'verified', domain: 'Boolean' },
      ],
    })
  })

  it('does not prompt for single-domain (boolean/json) columns', async () => {
    selectMock.mockResolvedValueOnce('users')
    multiselectMock.mockResolvedValueOnce(['verified'])

    const schema = await selectTableColumns(tables)

    // Only the table pick consumed a select; the boolean column did not.
    expect(selectMock).toHaveBeenCalledTimes(1)
    expect(schema?.columns).toEqual([{ name: 'verified', domain: 'Boolean' }])
  })

  it('returns undefined when the table prompt is cancelled', async () => {
    selectMock.mockResolvedValueOnce(CANCEL)
    expect(await selectTableColumns(tables)).toBeUndefined()
  })

  it('returns undefined when the column multiselect is cancelled', async () => {
    selectMock.mockResolvedValueOnce('users')
    multiselectMock.mockResolvedValueOnce(CANCEL)
    expect(await selectTableColumns(tables)).toBeUndefined()
  })

  it('returns undefined when a per-column domain prompt is cancelled', async () => {
    selectMock
      .mockResolvedValueOnce('users') // table pick
      .mockResolvedValueOnce(CANCEL) // email domain → cancelled
    multiselectMock.mockResolvedValueOnce(['email', 'age'])
    expect(await selectTableColumns(tables)).toBeUndefined()
  })

  it('pre-selects eql-encrypted columns and still assigns them a domain', async () => {
    const withEql = [
      {
        tableName: 'accounts',
        columns: [
          { columnName: 'ssn', dataType: 'text', udtName: 'eql_v2_encrypted', isEqlEncrypted: true },
        ],
      },
    ]
    selectMock
      .mockResolvedValueOnce('accounts') // table pick
      .mockResolvedValueOnce('TextSearch') // ssn domain
    multiselectMock.mockResolvedValueOnce(['ssn'])

    const schema = await selectTableColumns(withEql)

    // The "detected N pre-selected" notice fired for the eql column…
    expect(p.log.info).toHaveBeenCalled()
    // …and the column is mapped through pgTypeToDataType('eql_v2_encrypted')
    // which falls back to 'string', so it still receives its chosen domain.
    expect(schema?.columns).toEqual([{ name: 'ssn', domain: 'TextSearch' }])
  })
})
