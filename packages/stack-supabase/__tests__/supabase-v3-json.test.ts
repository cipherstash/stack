/**
 * Encrypted-JSON querying on the v3 supabase surface (#650): `contains()` on a
 * `types.Json` column (encrypted ste_vec containment), the JSONPath selector
 * methods (`selectorEq`/`selectorNe`), and the guards that keep the capability-
 * overloaded `cs` wire operator honest (free-text vs containment).
 *
 * Wire semantics (which overload PostgREST resolves, absent-path `ne`
 * inclusion) are proven live in `integration/json.integration.test.ts`; this
 * suite pins the ADAPTER's behaviour — operand routing, encryption calls, and
 * rejection surfaces — against mocks.
 */

import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it } from 'vitest'
import { EncryptedQueryBuilderV3Impl } from '../src/query-builder-v3'
import {
  createMockEncryptionClient,
  createMockSupabase,
} from './helpers/supabase-mock'

const events = encryptedTable('events', {
  payload: types.Json('payload'),
  name: types.TextSearch('name'),
})

const EVENTS_ALL_COLUMNS = ['id', 'payload', 'name', 'note']

function makeBuilder(resultData: unknown = []) {
  const supabase = createMockSupabase(resultData)
  const encryptionClient = createMockEncryptionClient()
  const builder = new EncryptedQueryBuilderV3Impl(
    'events',
    events,
    encryptionClient as never,
    supabase.client as never,
    EVENTS_ALL_COLUMNS,
  )
  return { supabase, builder }
}

/** The recorded wire call for a column's containment filter, parsed. */
function containsCall(
  supabase: ReturnType<typeof createMockSupabase>,
  method: 'filter' | 'not',
) {
  const call = supabase.calls.find((c) => c.method === method)
  expect(call).toBeDefined()
  return call as { method: string; args: unknown[] }
}

describe('contains() on an encrypted types.Json column', () => {
  it('storage-encrypts the sub-document and emits the cs wire operator', async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').contains('payload', { user: { role: 'admin' } })

    const call = containsCall(supabase, 'filter')
    expect(call.args[0]).toBe('payload')
    expect(call.args[1]).toBe('cs')
    // The operand is the JSON.stringify'd storage envelope of the WHOLE
    // sub-document — encrypted via encrypt/bulkEncrypt, never encryptQuery.
    const envelope = JSON.parse(call.args[2] as string)
    expect(envelope.pt).toEqual({ user: { role: 'admin' } })
    expect(envelope.i.c).toBe('payload')
  })

  it('accepts an array sub-document', async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').contains('payload', [{ tag: 'vip' }])
    const call = containsCall(supabase, 'filter')
    expect(JSON.parse(call.args[2] as string).pt).toEqual([{ tag: 'vip' }])
  })

  it('rejects a scalar operand with a sub-document steer', () => {
    const { builder } = makeBuilder()
    expect(() => builder.contains('payload', 'admin' as never)).toThrow(
      /takes a sub-document/,
    )
    expect(() => builder.contains('payload', null as never)).toThrow(
      /takes a sub-document/,
    )
  })

  it('still rejects contains() on an encrypted TEXT column (that is matches())', () => {
    const { builder } = makeBuilder()
    expect(() => builder.contains('name', { any: 'thing' })).toThrow(
      /native \(exact\) containment.*matches\(\)/s,
    )
  })

  it('still passes contains() through natively on a plaintext column', async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').contains('note', ['x'])
    // Plaintext containment takes the base path: the operand is formatted as a
    // native containment literal (never encrypted — no envelope in the operand).
    const call = containsCall(supabase, 'filter')
    expect(call.args[0]).toBe('note')
    expect(call.args[1]).toBe('cs')
    expect(String(call.args[2])).not.toContain('pt')
  })
})

describe('matches() vs encrypted JSON', () => {
  it('rejects matches() on a types.Json column with a contains/selector steer', () => {
    const { builder } = makeBuilder()
    expect(() => builder.matches('payload', 'admin')).toThrow(
      /does not apply to encrypted JSON column .*contains\(.*selectorEq\(/s,
    )
  })
})

describe('selectorEq()', () => {
  it('reconstructs the path-shaped needle and emits encrypted cs', async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').selectorEq('payload', '$.user.role', 'admin')

    const call = containsCall(supabase, 'filter')
    expect(call.args[1]).toBe('cs')
    expect(JSON.parse(call.args[2] as string).pt).toEqual({
      user: { role: 'admin' },
    })
  })

  it('accepts a bare dot path (no $ prefix)', async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').selectorEq('payload', 'user.age', 30)
    const call = containsCall(supabase, 'filter')
    expect(JSON.parse(call.args[2] as string).pt).toEqual({ user: { age: 30 } })
  })

  it('rejects invalid paths with the shared validation errors', () => {
    const { builder } = makeBuilder()
    expect(() => builder.selectorEq('payload', '$', 'x')).toThrow(
      /addresses no field/,
    )
    expect(() => builder.selectorEq('payload', '$.a[0]', 'x')).toThrow(
      /array\/wildcard syntax/,
    )
    expect(() => builder.selectorEq('payload', '$.a..b', 'x')).toThrow(
      /malformed/,
    )
    expect(() => builder.selectorEq('payload', '$.a.__proto__', 'x')).toThrow(
      /forbidden key/,
    )
  })

  it('rejects non-scalar leaves and null', () => {
    const { builder } = makeBuilder()
    expect(() =>
      builder.selectorEq('payload', '$.user', { role: 'admin' } as never),
    ).toThrow(/scalar leaf.*contains\(\)/s)
    expect(() =>
      builder.selectorEq('payload', '$.tags', ['vip'] as never),
    ).toThrow(/scalar leaf/)
    expect(() =>
      builder.selectorEq('payload', '$.user.role', null as never),
    ).toThrow(/non-null scalar/)
  })

  it('rejects a non-JSON column', () => {
    const { builder } = makeBuilder()
    expect(() => builder.selectorEq('name', '$.a', 'x')).toThrow(
      /requires an encrypted JSON \(types\.Json\) column/,
    )
    expect(() => builder.selectorEq('note', '$.a', 'x')).toThrow(
      /requires an encrypted JSON \(types\.Json\) column/,
    )
  })
})

describe('selectorNe()', () => {
  it('emits the negated containment (not + cs) of the reconstructed needle', async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').selectorNe('payload', '$.user.role', 'admin')

    const call = containsCall(supabase, 'not')
    expect(call.args[0]).toBe('payload')
    expect(call.args[1]).toBe('cs')
    expect(JSON.parse(call.args[2] as string).pt).toEqual({
      user: { role: 'admin' },
    })
  })

  it('shares selectorEq validation (path + leaf + column kind)', () => {
    const { builder } = makeBuilder()
    expect(() => builder.selectorNe('payload', '$.a[*]', 'x')).toThrow(
      /array\/wildcard/,
    )
    expect(() => builder.selectorNe('name', '$.a', 'x')).toThrow(
      /requires an encrypted JSON/,
    )
  })
})

describe('raw filter routing on a JSON column', () => {
  it("accepts .filter(col, 'cs', subdoc) — the raw containment spelling", async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').filter('payload', 'cs', { user: { age: 30 } })
    const call = containsCall(supabase, 'filter')
    expect(call.args[1]).toBe('cs')
    expect(JSON.parse(call.args[2] as string).pt).toEqual({ user: { age: 30 } })
  })

  it("rejects scalar ops (.filter(col, 'eq', …)) by capability", async () => {
    const { builder } = makeBuilder()
    const { error, status } = await builder
      .select('id')
      .filter('payload', 'eq', { a: 1 })
    expect(status).toBe(500)
    expect(error?.message).toMatch(/does not support equality queries/)
  })

  it('not(col, "contains", …) is allowed on a JSON column (exact negated containment)', async () => {
    const { supabase, builder } = makeBuilder()
    await builder.select('id').not('payload', 'contains', { a: 1 })
    const call = containsCall(supabase, 'not')
    expect(call.args[1]).toBe('cs')
  })

  it('not(col, "contains", …) stays rejected on an encrypted TEXT column', () => {
    const { builder } = makeBuilder()
    expect(() => builder.not('name', 'contains', 'x')).toThrow(
      /not.*fuzzy free-text matching/s,
    )
  })
})
