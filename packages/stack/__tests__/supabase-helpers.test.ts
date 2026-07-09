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

// ---------------------------------------------------------------------------
// `contains` is the ONLY FilterOp that is a supabase-js METHOD name rather than
// a PostgREST operator token. Every other member of the union (`eq`, `in`,
// `like`, `is`, …) spells the same in both. Left untranslated, `rebuildOrString`
// emits `tags.contains.vip`, which PostgREST rejects with PGRST100
// ("unexpected \"c\" expecting \"not\" or operator").
//
// Translating the operator alone is not enough: `cs` takes a CONTAINMENT
// literal, not the `(a,b)` list form arrays otherwise get, so `tags.cs.(vip)`
// fails with 22P02 ("malformed array literal"). Both halves are asserted here
// and executed against a real PostgREST in `supabase-v3-pgrest-live.test.ts`.
// ---------------------------------------------------------------------------

describe('rebuildOrString containment', () => {
  it("translates the `contains` FilterOp to PostgREST's `cs` token", () => {
    expect(rebuildOrString([cond('tags', 'contains', 'vip')])).toBe(
      'tags.cs.vip',
    )
  })

  it('formats an array operand as an array literal, not an in-list', () => {
    expect(rebuildOrString([cond('tags', 'contains', ['vip'])])).toBe(
      'tags.cs.{vip}',
    )
  })

  it('quotes a multi-element array literal, whose comma is reserved', () => {
    expect(rebuildOrString([cond('tags', 'contains', ['vip', 'admin'])])).toBe(
      'tags.cs."{vip,admin}"',
    )
  })

  it('quotes an array element that itself contains a comma', () => {
    // Inner array-literal quoting, then outer PostgREST quoting of the whole.
    expect(rebuildOrString([cond('tags', 'contains', ['with,comma'])])).toBe(
      'tags.cs."{\\"with,comma\\"}"',
    )
  })

  it('formats an object operand as a jsonb literal', () => {
    expect(rebuildOrString([cond('meta', 'contains', { a: 1 })])).toBe(
      'meta.cs."{\\"a\\":1}"',
    )
  })

  it('leaves an already-serialized encrypted envelope as a quoted scalar', () => {
    // The v3 encrypted operand is `JSON.stringify(envelope)` — a string, not an
    // array or object. It must keep taking the scalar quoting path.
    expect(rebuildOrString([cond('email', 'contains', ENVELOPE)])).toBe(
      `email.cs."{\\"v\\":1,\\"i\\":{\\"t\\":\\"users\\",\\"c\\":\\"email\\"},\\"c\\":\\"ct:abc\\"}"`,
    )
  })

  it('keeps the `cs` token a string-form caller already wrote', () => {
    expect(rebuildOrString([cond('tags', 'cs', ['vip', 'admin'])])).toBe(
      'tags.cs."{vip,admin}"',
    )
  })

  it('negates containment as `not.cs`', () => {
    expect(rebuildOrString([cond('tags', 'contains', ['vip'], true)])).toBe(
      'tags.not.cs.{vip}',
    )
  })

  it('still renders an `in` array as a parenthesized list', () => {
    expect(rebuildOrString([cond('nickname', 'in', ['ada', 'grace'])])).toBe(
      'nickname.in.(ada,grace)',
    )
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

// A containment literal carries top-level commas inside its braces
// (`tags.cs.{vip,admin}`). PostgREST's own logic-tree parser tracks those
// braces; ours must too, or the condition is split mid-literal into
// `tags.cs.{vip` plus a fragment `admin}` that has no dot and is dropped
// entirely — a filter that silently matches the wrong rows. Only or-strings
// that also reference an encrypted column are rebuilt from the parse, so this
// corrupts precisely the mixed encrypted/plaintext case.
describe('parseOrString containment literals', () => {
  it('does not split on a comma inside an array literal', () => {
    expect(parseOrString('note.eq.hello,tags.cs.{vip,admin}')).toEqual([
      { column: 'note', op: 'eq', negate: false, value: 'hello' },
      { column: 'tags', op: 'cs', negate: false, value: '{vip,admin}' },
    ])
  })

  it('does not split on a comma inside a jsonb literal', () => {
    expect(parseOrString('meta.cs.{"a":1,"b":2},note.eq.x')).toEqual([
      { column: 'meta', op: 'cs', negate: false, value: '{"a":1,"b":2}' },
      { column: 'note', op: 'eq', negate: false, value: 'x' },
    ])
  })

  it('round-trips a plaintext containment literal through rebuild', () => {
    const parsed = parseOrString('tags.cs.{vip,admin}')
    expect(rebuildOrString(parsed as DbPendingOrCondition[])).toBe(
      'tags.cs."{vip,admin}"',
    )
  })
})

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
