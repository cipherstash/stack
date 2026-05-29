import { describe, expect, it } from 'vitest'
import { castAsEnum, toEqlCastAs } from '../src/schema'
import { extractRegionFromCrn, normalizeCastAs } from '../src/wasm-inline'

// Exhaustive mapping the wasm-inline normaliser is expected to produce.
// If you add a variant to `castAsEnum`, add the corresponding EQL value
// here AND extend `toEqlCastAs()` — the test below catches the case
// where the enum gains a member but `toEqlCastAs` doesn't.
const EXPECTED_MAPPING: Readonly<Record<string, string>> = {
  bigint: 'big_int',
  boolean: 'boolean',
  date: 'date',
  number: 'double',
  string: 'text',
  json: 'jsonb',
  text: 'text',
}

describe('wasm-inline normalizeCastAs', () => {
  it('maps every SDK-facing CastAs variant to its EQL equivalent', () => {
    for (const sdkValue of castAsEnum.removeDefault().options) {
      const eql = toEqlCastAs(sdkValue)
      expect(eql, `toEqlCastAs("${sdkValue}") returned undefined`).toBeDefined()
      expect(eql).toBe(EXPECTED_MAPPING[sdkValue])
    }
  })

  it('catches schema drift — every castAsEnum value is in EXPECTED_MAPPING', () => {
    // If this fails, someone added a CastAs variant without extending
    // EXPECTED_MAPPING + toEqlCastAs. Update both before the WASM path
    // starts rejecting startup with "unknown variant 'null'".
    const enumKeys = new Set<string>(castAsEnum.removeDefault().options)
    const expectedKeys = new Set<string>(Object.keys(EXPECTED_MAPPING))
    expect(enumKeys, 'castAsEnum drifted from EXPECTED_MAPPING').toEqual(
      expectedKeys,
    )
  })

  it('rewrites cast_as on every column in a multi-table config', () => {
    const config = {
      v: 1,
      tables: {
        users: {
          email: { cast_as: 'string', indexes: { unique: {} } },
          age: { cast_as: 'number', indexes: {} },
        },
        orders: {
          total: { cast_as: 'bigint', indexes: {} },
        },
      },
    }

    const out = normalizeCastAs(config) as {
      v: number
      tables: Record<string, Record<string, { cast_as: string }>>
    }

    expect(out.tables.users.email.cast_as).toBe('text')
    expect(out.tables.users.age.cast_as).toBe('double')
    expect(out.tables.orders.total.cast_as).toBe('big_int')
  })

  it('preserves columns that omit cast_as', () => {
    const config = {
      v: 1,
      tables: { users: { email: { indexes: { unique: {} } } } },
    }

    const out = normalizeCastAs(config) as {
      tables: { users: { email: Record<string, unknown> } }
    }

    expect(out.tables.users.email).toEqual({ indexes: { unique: {} } })
    expect('cast_as' in out.tables.users.email).toBe(false)
  })

  it('throws synchronously when toEqlCastAs returns undefined', () => {
    // Simulate the drift scenario: a config carrying a cast_as value
    // that toEqlCastAs doesn't recognise. The normaliser must throw
    // with a clear message identifying the table.column, not hand
    // `undefined` through to WASM serde.
    const config = {
      v: 1,
      tables: {
        users: {
          // biome-ignore lint/suspicious/noExplicitAny: forcing drift for the test
          weird: { cast_as: 'uuid' as any, indexes: {} },
        },
      },
    }

    expect(() => normalizeCastAs(config)).toThrowError(
      /unrecognised cast_as value "uuid" on users\.weird/,
    )
  })
})

describe('wasm-inline extractRegionFromCrn', () => {
  it('pulls the region out of a well-formed workspace CRN', () => {
    expect(
      extractRegionFromCrn('crn:ap-southeast-2.aws:my-workspace-id'),
    ).toBe('ap-southeast-2.aws')
  })

  it('handles a plain region segment (no .aws suffix)', () => {
    expect(extractRegionFromCrn('crn:us-east-1:envWorkspace')).toBe(
      'us-east-1',
    )
  })

  it('throws on a CRN missing the workspace-id segment', () => {
    expect(() => extractRegionFromCrn('crn:ap-southeast-2.aws')).toThrowError(
      /invalid workspace CRN/,
    )
  })

  it('throws on a value that is not a CRN at all', () => {
    expect(() => extractRegionFromCrn('ap-southeast-2.aws')).toThrowError(
      /invalid workspace CRN/,
    )
  })
})
