/**
 * Wire-format tests: what PostgREST actually receives.
 *
 * These drive the real postgrest-js serializer (see `helpers/postgrest-wire`),
 * because the encrypted operand is `JSON.stringify(envelope)` — dense with `"`
 * and `,` — and postgrest-js's `in()`/`notIn()` wrap a comma-bearing element in
 * `"…"` WITHOUT escaping the quotes already inside it. The mock-based suites
 * assert the array handed to `.in()` and cannot see that.
 */

import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import { EncryptedQueryBuilderV3Impl } from '@/supabase/query-builder-v3'
import { createWirePostgrest } from './helpers/postgrest-wire'
import { createMockEncryptionClient } from './helpers/supabase-mock'

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  nickname: types.TextEq('nickname'),
})

const ALL_COLUMNS = ['id', 'email', 'nickname', 'note']

function wireInstance() {
  const wire = createWirePostgrest([])
  const builder = () =>
    new EncryptedQueryBuilderV3Impl(
      'users',
      users,
      createMockEncryptionClient(),
      wire.client,
      ALL_COLUMNS,
    )
  return { wire, builder }
}

/**
 * Split a PostgREST `(a,b)` list the way the server does: a `\` escapes the
 * next character, and a top-level `,` only separates when not inside quotes.
 * Returns each element with its quoting and escaping undone.
 */
function parseInList(operand: string, prefix: string): string[] {
  expect(operand.startsWith(`${prefix}.(`)).toBe(true)
  expect(operand.endsWith(')')).toBe(true)
  const inner = operand.slice(`${prefix}.(`.length, -1)

  const out: string[] = []
  let cur = ''
  let quoted = false
  let escaped = false
  for (const ch of inner) {
    if (escaped) {
      cur += ch
      escaped = false
    } else if (ch === '\\') {
      escaped = true
    } else if (ch === '"') {
      quoted = !quoted
    } else if (ch === ',' && !quoted) {
      out.push(cur)
      cur = ''
    } else {
      cur += ch
    }
  }
  out.push(cur)
  return out
}

describe('encrypted in() emits a parseable PostgREST operand', () => {
  it('escapes the quotes inside each encrypted element', async () => {
    const { wire, builder } = wireInstance()

    await builder().select('id').in('nickname', ['ada', 'grace'])

    const operand = wire.operandFor('nickname')
    // Unescaped, PostgREST terminates the value at the envelope's first `"`.
    expect(operand).toContain('\\"')

    const elements = parseInList(operand, 'in')
    expect(elements).toHaveLength(2)
    const plaintexts = elements.map((e) => JSON.parse(e).pt)
    expect(plaintexts).toEqual(['ada', 'grace'])
  })

  it('leaves a plaintext in() list alone', async () => {
    const { wire, builder } = wireInstance()

    await builder().select('id').in('note', ['x', 'y'])

    expect(wire.operandFor('note')).toBe('in.(x,y)')
  })
})

describe('encrypted not(col, in, …) emits a parseable PostgREST operand', () => {
  it('encrypts each element separately and escapes them', async () => {
    const { wire, builder } = wireInstance()

    await builder().select('id').not('nickname', 'in', ['ada', 'grace'])

    const operand = wire.operandFor('nickname')
    expect(operand.startsWith('not.in.(')).toBe(true)

    const elements = parseInList(operand, 'not.in')
    expect(elements).toHaveLength(2)
    const plaintexts = elements.map((e) => JSON.parse(e).pt)
    // The whole array must never be encrypted as ONE ciphertext.
    expect(plaintexts).toEqual(['ada', 'grace'])
  })

  it('leaves a plaintext not-in list alone', async () => {
    const { wire, builder } = wireInstance()

    await builder().select('id').not('note', 'in', ['x', 'y'])

    expect(wire.operandFor('note')).toBe('not.in.(x,y)')
  })

  // A PostgREST list literal cannot be encrypted element-wise, and encrypting
  // it whole silently matches nothing. Fail loudly instead.
  it('rejects a PostgREST list literal on an encrypted column', async () => {
    const { builder } = wireInstance()

    const { error, status } = await builder()
      .select('id')
      .not('nickname', 'in', '(ada,grace)')

    expect(status).toBe(500)
    expect(error?.message).toMatch(/requires an array of values/)
  })
})
