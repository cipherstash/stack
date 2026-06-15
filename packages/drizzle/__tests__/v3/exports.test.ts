import { PgDialect, pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import * as v3 from '../../src/pg/v3/index'
import { createMockProtectClient } from '../test-utils'

describe('./pg/v3 export surface', () => {
  it('exposes the v3 builder, dialect, and shared helpers', () => {
    expect(typeof v3.eqlV3Type).toBe('function')
    expect(typeof v3.createProtectOperators).toBe('function')
    expect(typeof v3.createProtectOperatorsV3).toBe('function')
    expect(typeof v3.extractProtectSchema).toBe('function')
    expect(v3.v3Dialect).toBeDefined()
  })

  // On the v3 subpath, BOTH the bare `createProtectOperators` and the explicit
  // `createProtectOperatorsV3` alias must be v3-bound — the v2-defaulted factory must
  // not be reachable here, or a v3 consumer would silently emit failing v2 SQL.
  it.each(['createProtectOperators', 'createProtectOperatorsV3'] as const)(
    '%s on the v3 subpath pre-binds the v3 dialect (emits eq_term, not native =)',
    async (factory) => {
      const table = pgTable(`v3_wrap_${factory}`, {
        t_eq: v3.eqlV3Type<string>('t_eq', {
          dataType: 'text',
          index: 'equality',
        }),
      })
      const { client } = createMockProtectClient()
      const ops = v3[factory](client)
      const query = new PgDialect().sqlToQuery(
        await ops.eq(table.t_eq, 'alice'),
      )
      expect(query.sql).toContain('eql_v3.eq_term(')
      expect(query.sql).not.toContain('"t_eq" = $')
    },
  )
})
