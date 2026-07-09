import { describe, expect, it } from 'vitest'
import {
  addJsonbCastsV3,
  parseOrString,
  rebuildOrString,
} from '@/supabase/helpers'

// `createdAt` is a renamed property (DB column `created_at`); `email` is a
// property whose name already equals its DB column.
const propToDb = { createdAt: 'created_at', email: 'email' }

describe('addJsonbCastsV3', () => {
  it('aliases a renamed property to its DB name', () => {
    expect(addJsonbCastsV3('createdAt', propToDb)).toBe(
      'createdAt:created_at::jsonb',
    )
  })

  it('casts a property whose name equals its DB name in place', () => {
    expect(addJsonbCastsV3('email', propToDb)).toBe('email::jsonb')
  })

  it('casts a raw DB name in place, without aliasing', () => {
    expect(addJsonbCastsV3('created_at', propToDb)).toBe('created_at::jsonb')
  })

  it('resolves an already-aliased token whose name is a property', () => {
    expect(addJsonbCastsV3('e:createdAt', propToDb)).toBe('e:created_at::jsonb')
  })

  it('resolves an already-aliased token whose name is a raw DB name', () => {
    expect(addJsonbCastsV3('e:created_at', propToDb)).toBe(
      'e:created_at::jsonb',
    )
  })

  it('leaves an aliased token naming an unknown column untouched', () => {
    expect(addJsonbCastsV3('e:other', propToDb)).toBe('e:other')
  })

  it('leaves already-cast tokens untouched', () => {
    expect(addJsonbCastsV3('email::text', propToDb)).toBe('email::text')
  })

  it('leaves function calls untouched', () => {
    expect(addJsonbCastsV3('count(email)', propToDb)).toBe('count(email)')
  })

  it('leaves foreign-table (dotted) tokens untouched', () => {
    expect(addJsonbCastsV3('t.email', propToDb)).toBe('t.email')
  })

  // `lookupDbName`'s `Object.hasOwn` guard. Without it an inherited
  // `Object.prototype` member resolves truthy and gets interpolated into the
  // emitted select string (e.g. `function Object() { … }::jsonb`).
  it('does not resolve a bare Object.prototype key as a property', () => {
    expect(addJsonbCastsV3('constructor', propToDb)).toBe('constructor')
  })

  it('does not resolve an Object.prototype key inside an alias', () => {
    expect(addJsonbCastsV3('a:toString', propToDb)).toBe('a:toString')
  })

  it('maps each token of a multi-column select independently', () => {
    expect(addJsonbCastsV3('id, email, createdAt', propToDb)).toBe(
      'id, email::jsonb, createdAt:created_at::jsonb',
    )
  })
})

// ---------------------------------------------------------------------------
// .or() operand quoting
//
// Every v3 encrypted operand is `JSON.stringify(envelope)` — dense with double
// quotes and commas. `formatOrValue` wraps a comma-bearing value in quotes but
// never escapes the quotes already inside it, so PostgREST terminates the value
// at the first inner `"`. Pre-existing in v2 (its composite literal also
// carries quotes); v3 makes it certain to fire.
// ---------------------------------------------------------------------------

const ENVELOPE = '{"v":1,"i":{"t":"users","c":"email"},"c":"ct:abc"}'

describe('rebuildOrString quoting', () => {
  it('escapes the double quotes inside a quoted operand', () => {
    const out = rebuildOrString([
      { column: 'email', op: 'eq', value: ENVELOPE },
    ])
    // The operand must be one quoted token whose inner quotes are escaped.
    expect(out).toBe(
      `email.eq."{\\"v\\":1,\\"i\\":{\\"t\\":\\"users\\",\\"c\\":\\"email\\"},\\"c\\":\\"ct:abc\\"}"`,
    )
  })

  it('escapes a backslash before escaping quotes', () => {
    expect(rebuildOrString([{ column: 'a', op: 'eq', value: 'x\\y,z' }])).toBe(
      'a.eq."x\\\\y,z"',
    )
  })

  it('quotes a value containing a bare double quote even without a comma', () => {
    expect(rebuildOrString([{ column: 'a', op: 'eq', value: 'he"llo' }])).toBe(
      'a.eq."he\\"llo"',
    )
  })

  it('leaves a value with no reserved characters unquoted', () => {
    expect(rebuildOrString([{ column: 'a', op: 'eq', value: 'plain' }])).toBe(
      'a.eq.plain',
    )
  })
})

describe('parseOrString / rebuildOrString round-trip', () => {
  it('round-trips an encrypted JSON envelope operand', () => {
    const conditions = [{ column: 'email', op: 'eq' as const, value: ENVELOPE }]
    expect(parseOrString(rebuildOrString(conditions))).toEqual(conditions)
  })

  it('round-trips a value carrying backslashes and quotes', () => {
    const conditions = [{ column: 'a', op: 'eq' as const, value: 'x\\"y,z' }]
    expect(parseOrString(rebuildOrString(conditions))).toEqual(conditions)
  })

  it('does not split on a comma inside a quoted operand', () => {
    const s = rebuildOrString([
      { column: 'email', op: 'eq', value: ENVELOPE },
      { column: 'id', op: 'eq', value: '7' },
    ])
    const parsed = parseOrString(s)
    expect(parsed).toHaveLength(2)
    expect(parsed[0].value).toBe(ENVELOPE)
    expect(parsed[1].value).toBe('7')
  })
})
