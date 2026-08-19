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
  pgcryptoSchema: 'extensions',
  eqlV3SchemaPresent: false,
  eqlV3InternalSchemaPresent: false,
  canDropEqlV3Schema: null,
  canDropEqlV3InternalSchema: null,
  canCreateOperatorClass: true,
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

  it('flags a relocated pgcrypto and shows its schema', () => {
    const report = renderPreflightReport({
      ...CAPABLE,
      pgcryptoSchema: 'crypto_home',
      missing: ['x'],
      ok: false,
    })
    expect(report).toContain('present (in crypto_home)')
    expect(report).toContain('<- blocks: not on the EQL search_path')
  })

  // #891: the ORE trade is reported so it is known before a schema is
  // written. It must never read as a blocker — the bundle's fallback makes an
  // install without the operator class a complete install.
  it('names the ORE consequence for a role that cannot create an operator class', () => {
    const report = renderPreflightReport({
      ...CAPABLE,
      currentUser: 'sandbox_exec',
      isSuperuser: false,
      canCreateOperatorClass: false,
    })
    expect(report).toMatch(/ORE operator class\s+not creatable/)
    expect(report).toContain('<- skips: ORE opclass')
    expect(report).toContain('`types.*Ord`, not `types.*OrdOre`')
    expect(report).not.toContain('<- blocks')
  })

  it('leaves the ORE row unannotated for a role that can create one', () => {
    const report = renderPreflightReport(CAPABLE)
    expect(report).toMatch(/ORE operator class\s+creatable/)
    expect(report).not.toContain('<- skips: ORE opclass')
  })

  // A probe that could not ask the question must not be rendered as either
  // answer — "unknown" is the honest third state.
  it('renders an unanswerable ORE probe as unknown, not as no', () => {
    const report = renderPreflightReport({
      ...CAPABLE,
      canCreateOperatorClass: null,
    })
    expect(report).toMatch(/ORE operator class\s+unknown/)
    expect(report).toContain('`stash eql verify` reports it after install')
    expect(report).not.toContain('not creatable')
  })

  it('adds the drop-ownership row only when an EQL schema exists', () => {
    expect(renderPreflightReport(CAPABLE)).not.toContain('can drop EQL schemas')
    const blocked = renderPreflightReport({
      ...CAPABLE,
      eqlV3SchemaPresent: true,
      eqlV3InternalSchemaPresent: true,
      canDropEqlV3Schema: false,
      canDropEqlV3InternalSchema: false,
      missing: ['x'],
      ok: false,
    })
    expect(blocked).toContain('can drop EQL schemas  no')
    expect(blocked).toContain('<- blocks: reinstall')
    const fine = renderPreflightReport({
      ...CAPABLE,
      eqlV3SchemaPresent: true,
      canDropEqlV3Schema: true,
      canDropEqlV3InternalSchema: true,
    })
    expect(fine).toContain('can drop EQL schemas  yes')
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
