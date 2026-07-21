import type { JsonDocument } from '@cipherstash/stack/eql/v3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type {
  JsonIntegrationAdapter,
  JsonQueryOp,
  JsonSeedRow,
} from './json-adapter.ts'

const DOCUMENTS = {
  ada: {
    user: 'ada@example.com',
    roles: ['admin', 'eng'],
    active: true,
    age: 30,
  },
  grace: { user: 'grace@example.com', roles: ['eng'], age: 20 },
  zoe: {
    user: 'zoe@example.com',
    roles: ['ops'],
    active: false,
    age: 40,
  },
  // No `$.age`: comparisons exclude it except `ne`; ORDER BY observes the
  // extracted SQL NULL using PostgreSQL's default NULL placement.
  noage: { user: 'noage@example.com', roles: ['ops'] },
} as const satisfies Record<string, JsonDocument>

const ROWS: readonly JsonSeedRow[] = Object.entries(DOCUMENTS).map(
  ([rowKey, document]) => ({ rowKey, document }),
)

/**
 * Shared live-PG contract for every first-party adapter that can express EQL
 * v3 typed JSON query operands. Keeping the assertions here prevents Drizzle
 * and Prisma Next from quietly claiming different JSON coverage.
 */
export function runJsonSuite(makeAdapter: () => JsonIntegrationAdapter): void {
  const adapter = makeAdapter()
  const runId = Math.random().toString(36).slice(2, 8)

  describe(`v3 ${adapter.name} — encrypted JSON`, () => {
    beforeAll(async () => {
      await adapter.setup({
        name: `v3_it_json_${adapter.name.replace('-', '_')}_${runId}`,
        rows: ROWS,
      })
    }, 300_000)

    afterAll(async () => {
      await adapter.teardown()
    })

    const expectRows = async (op: JsonQueryOp, expected: string[]) => {
      const rows = await adapter.run(op)
      expect([...rows].sort()).toEqual([...expected].sort())
    }

    describe('containment', () => {
      it('matches array-element containment', async () => {
        await expectRows({ kind: 'contains', value: { roles: ['eng'] } }, [
          'ada',
          'grace',
        ])
      })

      it('matches scalar and boolean fields exactly', async () => {
        await expectRows(
          { kind: 'contains', value: { user: 'zoe@example.com' } },
          ['zoe'],
        )
        await expectRows({ kind: 'contains', value: { active: true } }, ['ada'])
      })

      it('returns no rows for an absent sub-document', async () => {
        await expectRows({ kind: 'contains', value: { roles: ['nope'] } }, [])
      })

      it('rejects an empty object instead of matching every document', async () => {
        await expect(
          adapter.run({ kind: 'contains', value: {} }),
        ).rejects.toThrow(/matches every row/)
      })
    })

    describe('selector comparisons', () => {
      it('matches exact numeric and string leaves', async () => {
        await expectRows(
          {
            kind: 'selector',
            comparison: 'eq',
            path: '$.age',
            value: 30,
          },
          ['ada'],
        )
        await expectRows(
          {
            kind: 'selector',
            comparison: 'eq',
            path: '$.user',
            value: 'zoe@example.com',
          },
          ['zoe'],
        )
      })

      it.each([
        ['gt', 25, ['ada', 'zoe']],
        ['lt', 35, ['ada', 'grace']],
        ['gte', 30, ['ada', 'zoe']],
        ['gt', 100, []],
      ] as const)('%s(%s) matches the plaintext oracle', async (comparison, value, expected) => {
        await expectRows(
          { kind: 'selector', comparison, path: '$.age', value },
          [...expected],
        )
      })

      it('uses explicit absent-path semantics', async () => {
        await expectRows(
          {
            kind: 'selector',
            comparison: 'eq',
            path: '$.age',
            value: 30,
          },
          ['ada'],
        )
        await expectRows(
          {
            kind: 'selector',
            comparison: 'ne',
            path: '$.age',
            value: 30,
          },
          ['grace', 'noage', 'zoe'],
        )
        await expectRows(
          {
            kind: 'selector',
            comparison: 'gt',
            path: '$.age',
            value: 0,
          },
          ['ada', 'grace', 'zoe'],
        )
      })

      it('rejects non-scalar leaves and unsupported paths', async () => {
        await expect(
          adapter.run({
            kind: 'selector',
            comparison: 'eq',
            path: '$.age',
            value: { nested: 1 },
          }),
        ).rejects.toThrow(/scalar leaf/)
        await expect(
          adapter.run({
            kind: 'selector',
            comparison: 'eq',
            path: '$.items[0].name',
            value: 'x',
          }),
        ).rejects.toThrow(/not yet supported|array\/wildcard syntax/)
      })
    })

    describe('selector ordering', () => {
      it('orders by eql_v3.ord_term of the selected entry', async () => {
        expect(
          await adapter.run({
            kind: 'selectorOrder',
            path: '$.age',
            direction: 'asc',
          }),
        ).toEqual(['grace', 'ada', 'zoe', 'noage'])

        expect(
          await adapter.run({
            kind: 'selectorOrder',
            path: '$.age',
            direction: 'desc',
          }),
        ).toEqual(['noage', 'zoe', 'ada', 'grace'])
      })

      it('rejects unsupported selector paths before querying', async () => {
        await expect(
          adapter.run({
            kind: 'selectorOrder',
            path: '$.items[0].age',
            direction: 'asc',
          }),
        ).rejects.toThrow(/not yet supported|array\/wildcard syntax/)
      })
    })
  })
}
