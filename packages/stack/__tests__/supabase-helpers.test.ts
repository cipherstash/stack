import { describe, expect, it } from 'vitest'
import {
  addJsonbCastsV3,
  parseOrString,
  rebuildOrString,
} from '@/supabase/helpers'
import type { DbPendingOrCondition } from '@/supabase/types'

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

  // Pins the leading-whitespace capture: drop it and ` email` loses its space.
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

/** `rebuildOrString` takes DB-space conditions; `column` is a branded `DbName`. */
function cond(column: string, op: string, value: unknown, negate?: boolean) {
  return { column, op, value, negate } as unknown as DbPendingOrCondition
}

describe('rebuildOrString quoting', () => {
  it('escapes the double quotes inside a quoted operand', () => {
    const out = rebuildOrString([cond('email', 'eq', ENVELOPE)])
    // The operand must be one quoted token whose inner quotes are escaped.
    expect(out).toBe(
      `email.eq."{\\"v\\":1,\\"i\\":{\\"t\\":\\"users\\",\\"c\\":\\"email\\"},\\"c\\":\\"ct:abc\\"}"`,
    )
  })

  it('escapes a backslash before escaping quotes', () => {
    expect(rebuildOrString([cond('a', 'eq', 'x\\y,z')])).toBe('a.eq."x\\\\y,z"')
  })

  it('quotes a value containing a bare double quote even without a comma', () => {
    expect(rebuildOrString([cond('a', 'eq', 'he"llo')])).toBe('a.eq."he\\"llo"')
  })

  it('leaves a value with no reserved characters unquoted', () => {
    expect(rebuildOrString([cond('a', 'eq', 'plain')])).toBe('a.eq.plain')
  })
})

describe('parseOrString / rebuildOrString round-trip', () => {
  it('round-trips an encrypted JSON envelope operand', () => {
    const conditions = [
      { column: 'email', op: 'eq', negate: false, value: ENVELOPE },
    ]
    expect(
      parseOrString(
        rebuildOrString(conditions.map((c) => cond(c.column, c.op, c.value))),
      ),
    ).toEqual(conditions)
  })

  it('round-trips a value carrying backslashes and quotes', () => {
    const conditions = [
      { column: 'a', op: 'eq', negate: false, value: 'x\\"y,z' },
    ]
    expect(
      parseOrString(
        rebuildOrString(conditions.map((c) => cond(c.column, c.op, c.value))),
      ),
    ).toEqual(conditions)
  })

  it('does not split on a comma inside a quoted operand', () => {
    const s = rebuildOrString([
      cond('email', 'eq', ENVELOPE),
      cond('id', 'eq', '7'),
    ])
    const parsed = parseOrString(s)
    expect(parsed).toHaveLength(2)
    expect(parsed[0].value).toBe(ENVELOPE)
    expect(parsed[1].value).toBe('7')
  })
})

// ---------------------------------------------------------------------------
// PostgREST negation inside .or()
//
// The parser split on the first two dots, so `col.not.in.(a,b)` yielded
// `{ op: 'not', value: 'in.(a,b)' }`. On a plaintext column that round-tripped
// by accident (rebuild re-joins the pieces verbatim). On an ENCRYPTED column the
// literal string `in.(a,b)` was encrypted as one plaintext, producing a filter
// that silently matched nothing.
// ---------------------------------------------------------------------------

describe('parseOrString negation', () => {
  it('lifts a not. prefix off the operator', () => {
    expect(parseOrString('nickname.not.eq.ada')).toEqual([
      { column: 'nickname', op: 'eq', negate: true, value: 'ada' },
    ])
  })

  it('parses a negated in-list as a real list, not a literal string', () => {
    expect(parseOrString('nickname.not.in.(ada,grace)')).toEqual([
      { column: 'nickname', op: 'in', negate: true, value: ['ada', 'grace'] },
    ])
  })

  it('parses not.is.null', () => {
    expect(parseOrString('email.not.is.null')).toEqual([
      { column: 'email', op: 'is', negate: true, value: null },
    ])
  })

  it('leaves a non-negated condition unnegated', () => {
    expect(parseOrString('nickname.in.(ada,grace)')).toEqual([
      { column: 'nickname', op: 'in', negate: false, value: ['ada', 'grace'] },
    ])
  })

  it('does not mistake a column or value named "not" for the prefix', () => {
    expect(parseOrString('not.eq.ada')).toEqual([
      { column: 'not', op: 'eq', negate: false, value: 'ada' },
    ])
    expect(parseOrString('nickname.eq.not')).toEqual([
      { column: 'nickname', op: 'eq', negate: false, value: 'not' },
    ])
  })

  it('does not swallow a condition whose not. prefix has no operator', () => {
    // `col.not.<value>` is malformed PostgREST. Consuming the prefix would leave
    // no operator, and the condition would be silently DROPPED from the or-string
    // — quietly widening the result set. Pass it through so PostgREST rejects it.
    expect(parseOrString('nickname.not.ada')).toEqual([
      { column: 'nickname', op: 'not', negate: false, value: 'ada' },
    ])
    expect(
      rebuildOrString(
        parseOrString('nickname.not.ada') as DbPendingOrCondition[],
      ),
    ).toBe('nickname.not.ada')
  })
})

describe('rebuildOrString negation', () => {
  it('re-emits the not. prefix', () => {
    expect(rebuildOrString([cond('nickname', 'eq', 'ada', true)])).toBe(
      'nickname.not.eq.ada',
    )
  })

  it('round-trips a negated in-list through parse → rebuild', () => {
    const parsed = parseOrString('nickname.not.in.(ada,grace)')
    expect(rebuildOrString(parsed as DbPendingOrCondition[])).toBe(
      'nickname.not.in.(ada,grace)',
    )
  })

  it('omits the prefix when negate is false or absent', () => {
    expect(rebuildOrString([cond('nickname', 'eq', 'ada', false)])).toBe(
      'nickname.eq.ada',
    )
    expect(rebuildOrString([cond('nickname', 'eq', 'ada')])).toBe(
      'nickname.eq.ada',
    )
  })
})
