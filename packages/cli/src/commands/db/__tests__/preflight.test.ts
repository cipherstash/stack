import { describe, expect, it } from 'vitest'
import type { PreflightResult } from '@/installer/index.js'
import { renderPreflightReport } from '../preflight.js'

const CAPABLE: PreflightResult = {
  currentUser: 'postgres',
  isSuperuser: true,
  memberOfPostgres: true,
  hasDatabaseCreate: true,
  hasPublicCreate: true,
  pgcryptoInstalled: true,
  eqlV3SchemaPresent: false,
  eqlV3InternalSchemaPresent: false,
  missing: [],
  ok: true,
}

describe('renderPreflightReport', () => {
  it('renders every row, with no annotations for a capable role', () => {
    const report = renderPreflightReport(CAPABLE)
    expect(report).toContain('current_user')
    expect(report).toContain('postgres')
    expect(report).toContain('member of postgres  yes')
    expect(report).toContain('eql_v3 schema')
    expect(report).toContain('eql_v3_internal')
    expect(report).not.toContain('<- blocks')
  })

  it('annotates a non-member role with the statement it blocks', () => {
    const report = renderPreflightReport({
      ...CAPABLE,
      currentUser: 'sandbox_exec',
      isSuperuser: false,
      memberOfPostgres: false,
    })
    expect(report).toContain('member of postgres  no')
    expect(report).toContain(
      '<- skips optional: ALTER DEFAULT PRIVILEGES FOR ROLE postgres',
    )
  })

  it('marks a database with no postgres role as n/a rather than yes/no', () => {
    const report = renderPreflightReport({
      ...CAPABLE,
      memberOfPostgres: null,
    })
    expect(report).toContain('n/a (no postgres role)')
  })

  it('annotates each missing privilege with what it blocks', () => {
    const report = renderPreflightReport({
      ...CAPABLE,
      currentUser: 'sandbox_exec',
      isSuperuser: false,
      memberOfPostgres: false,
      hasDatabaseCreate: false,
      hasPublicCreate: false,
      pgcryptoInstalled: false,
      missing: ['x', 'y', 'z'],
      ok: false,
    })
    expect(report).toContain('<- blocks: CREATE SCHEMA / CREATE EXTENSION')
    expect(report).toContain('<- blocks: CREATE DOMAIN public.eql_v3_*')
    expect(report).toContain('<- blocks: CREATE EXTENSION pgcrypto')
  })

  it('suppresses privilege annotations for a superuser', () => {
    const report = renderPreflightReport({
      ...CAPABLE,
      // A superuser row can carry has_* = false on exotic setups; the role
      // still installs fine, so nothing should read as blocked.
      hasDatabaseCreate: false,
      hasPublicCreate: false,
      pgcryptoInstalled: false,
    })
    expect(report).not.toContain('<- blocks: CREATE')
  })
})
