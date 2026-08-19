import { readInstallSql } from '@cipherstash/eql/sql'
import { describe, expect, it } from 'vitest'
import {
  diffSurface,
  type ExpectedSurface,
  type InstalledSurface,
  parseExpectedSurface,
} from '../verify.js'

/**
 * The parser side runs against the REAL pinned bundle, not a fixture: the
 * whole point of #890 is that the expected surface tracks what the bundle
 * actually installs, so the assertions here pin known members and internal
 * consistency rather than a fixture that could drift from the dependency.
 */
const expected = parseExpectedSurface(readInstallSql())

describe('parseExpectedSurface (pinned bundle)', () => {
  it('names the two EQL schemas', () => {
    expect(expected.schemas).toEqual(['eql_v3', 'eql_v3_internal'])
  })

  it('finds the storage domains and their query-operand twins', () => {
    // The issue's reported domain, both halves.
    expect(expected.domains).toContain('public.eql_v3_double_ord')
    expect(expected.domains).toContain('eql_v3.query_double_ord')
    // Domains are created inside IF NOT EXISTS DO blocks — a parser that only
    // reads column-0 statements finds none of them.
    expect(expected.domains.length).toBeGreaterThan(90)
    // Every queryable public domain (capability suffix) has a query twin;
    // the storage-only base domains (`eql_v3_bigint`, …) do not.
    for (const domain of expected.domains) {
      const scalar =
        /^public\.eql_v3_(.+_(?:eq|ord|ope|ore|match|search))$/.exec(domain)
      // `eql_v3_json_search`'s query twin is `query_json` (reached via the
      // bundle's cast), not `query_json_search` — skip it here.
      if (scalar && scalar[1] !== 'json_search') {
        expect(expected.domains).toContain(`eql_v3.query_${scalar[1]}`)
      }
    }
  })

  it('derives the ORE-carrying domains for the fallback model', () => {
    expect(expected.oreDomains).toContain('public.eql_v3_double_ord_ore')
    expect(expected.oreDomains).toContain('eql_v3.query_text_search_ore')
    expect(expected.oreDomains.every((domain) => domain.endsWith('_ore'))).toBe(
      true,
    )
    // 9 scalar `_ord_ore` + `text_search_ore`, each with a query twin.
    expect(expected.oreDomains).toHaveLength(20)
  })

  it('collects type-only signatures per name, including quoted names and aggregates', () => {
    // Zero-arg signature is the empty string.
    expect(expected.functions.get('eql_v3.version')).toEqual([''])
    // The term extractors — one overload per queryable domain, each keyed by
    // its argument type so a stale same-name function cannot stand in for it.
    const eqTerm = expected.functions.get('eql_v3.eq_term') ?? []
    expect(eqTerm.length).toBeGreaterThan(5)
    expect(eqTerm).toContain('public.eql_v3_text_eq')
    // Quoted operator-implementation names are stored unquoted, as pg_proc
    // spells them.
    expect(
      (expected.functions.get('eql_v3_internal.-') ?? []).length,
    ).toBeGreaterThan(0)
    // Aggregates share pg_proc with functions, so they share the map — and
    // their argument lists are types-only already.
    expect(expected.functions.get('eql_v3.min') ?? []).toContain(
      'public.eql_v3_json_entry',
    )
    expect((expected.functions.get('eql_v3.max') ?? []).length).toBeGreaterThan(
      0,
    )
  })

  it('excludes the bundle-conditional objects (DO-block bodies)', () => {
    // Created only when the ORE opclass could NOT be created — expecting it
    // unconditionally would report damage on every superuser install.
    expect(
      expected.functions.has('eql_v3_internal.ore_domain_unavailable'),
    ).toBe(false)
  })

  it('extracts operator identities by operand types', () => {
    // The exact predicate from #890: `weight >= x` on a double_ord column.
    expect(expected.operators).toContain(
      '>= (public.eql_v3_double_ord, public.eql_v3_double_ord)',
    )
    expect(expected.operators).toContain('>= (public.eql_v3_double_ord, jsonb)')
    // text[] and text RHS variants must stay distinct operators.
    expect(expected.operators).toContain('- (public.eql_v3_bigint, text)')
    expect(expected.operators).toContain('- (public.eql_v3_bigint, text[])')
    expect(expected.operators.length).toBeGreaterThan(2000)
  })

  it('extracts the cast', () => {
    expect(expected.casts).toContain(
      'public.eql_v3_json_search AS eql_v3.query_json',
    )
  })
})

/** A database that has exactly what the bundle installs, superuser flavour. */
function completeInstall(
  surface: ExpectedSurface,
  overrides: Partial<InstalledSurface> = {},
): InstalledSurface {
  return {
    eqlV3SchemaPresent: true,
    eqlV3InternalSchemaPresent: true,
    pgcryptoInstalled: true,
    pgcryptoSchema: 'extensions',
    installedVersion: surface.eqlVersion,
    presentTypes: new Set([...surface.domains, ...surface.types]),
    functionSignatures: new Map(
      [...surface.functions].map(([name, signatures]) => [
        name,
        new Set(signatures),
      ]),
    ),
    presentOperators: new Set(surface.operators),
    presentCasts: new Set(surface.casts),
    oreOpclassPresent: true,
    poisonedDomains: 0,
    ...overrides,
  }
}

describe('diffSurface', () => {
  it('reports a complete superuser install as complete and ORE-indexable', () => {
    const report = diffSurface(expected, completeInstall(expected))
    expect(report.status).toBe('complete')
    expect(report.ok).toBe(true)
    expect(report.ore?.state).toBe('indexable')
    expect(report.findings.filter((f) => f.severity === 'damage')).toHaveLength(
      0,
    )
  })

  it('reads the managed-Postgres ORE skip as expected, not damage', () => {
    const report = diffSurface(
      expected,
      completeInstall(expected, {
        oreOpclassPresent: false,
        poisonedDomains: expected.oreDomains.length,
      }),
    )
    expect(report.status).toBe('complete')
    expect(report.ore?.state).toBe('fallback')
    const skip = report.findings.find((f) => f.kind === 'opclass')
    expect(skip?.severity).toBe('expected')
  })

  it('flags an absent opclass with an incomplete poison fallback as damage', () => {
    const report = diffSurface(
      expected,
      completeInstall(expected, {
        oreOpclassPresent: false,
        poisonedDomains: 0,
      }),
    )
    expect(report.status).toBe('incomplete')
    expect(report.ore?.state).toBe('incoherent-unpoisoned')
  })

  it('flags leftover poison constraints alongside a present opclass as damage', () => {
    const report = diffSurface(
      expected,
      completeInstall(expected, { poisonedDomains: 3 }),
    )
    expect(report.status).toBe('incomplete')
    expect(report.ore?.state).toBe('incoherent-poisoned')
  })

  it('detects a missing operator and attributes it to its domain', () => {
    const operators = new Set(expected.operators)
    operators.delete('>= (public.eql_v3_double_ord, public.eql_v3_double_ord)')
    const report = diffSurface(
      expected,
      completeInstall(expected, { presentOperators: operators }),
    )
    expect(report.status).toBe('incomplete')
    const finding = report.findings.find(
      (f) => f.kind === 'operator' && f.severity === 'damage',
    )
    expect(finding?.domain).toBe('eql_v3_double_ord')
    expect(report.counts?.operators.present).toBe(expected.operators.length - 1)
  })

  it('detects a wholly missing function and names a missing overload by signature', () => {
    const installed = completeInstall(expected)
    installed.functionSignatures.delete('eql_v3.eq_term')
    const ordSignatures = installed.functionSignatures.get('eql_v3.ord_term')
    expect(ordSignatures?.has('public.eql_v3_text_ord')).toBe(true)
    ordSignatures?.delete('public.eql_v3_text_ord')
    const report = diffSurface(expected, installed)
    expect(report.status).toBe('incomplete')
    const messages = report.findings
      .filter((f) => f.kind === 'function')
      .map((f) => f.message)
    expect(
      messages.some((m) => m.includes('`eql_v3.eq_term` is missing')),
    ).toBe(true)
    // The missing overload is named by its argument types, not a count.
    expect(messages).toContain(
      'Function `eql_v3.ord_term(public.eql_v3_text_ord)` is missing.',
    )
  })

  it('is not fooled by a stale same-name function standing in for a missing overload', () => {
    // The count-level trap: 1 current overload removed, 1 impostor added —
    // the per-name COUNT is unchanged, but the signature diff still names
    // the missing one. This is the #890 false-negative class.
    const installed = completeInstall(expected)
    const ordSignatures = installed.functionSignatures.get('eql_v3.ord_term')
    ordSignatures?.delete('public.eql_v3_text_ord')
    ordSignatures?.add('public.some_hand_rolled_type')
    const report = diffSurface(expected, installed)
    expect(report.status).toBe('incomplete')
    expect(
      report.findings.some((f) =>
        f.message.includes(
          'Function `eql_v3.ord_term(public.eql_v3_text_ord)` is missing.',
        ),
      ),
    ).toBe(true)
  })

  it('detects a missing domain', () => {
    const types = new Set([...expected.domains, ...expected.types])
    types.delete('public.eql_v3_double_ord')
    const report = diffSurface(
      expected,
      completeInstall(expected, { presentTypes: types }),
    )
    expect(report.status).toBe('incomplete')
    const finding = report.findings.find((f) => f.kind === 'domain')
    expect(finding?.message).toContain('public.eql_v3_double_ord')
    expect(finding?.domain).toBe('eql_v3_double_ord')
  })

  it('reports not-installed when the eql_v3 schema is absent', () => {
    const report = diffSurface(
      expected,
      completeInstall(expected, {
        eqlV3SchemaPresent: false,
        installedVersion: null,
      }),
    )
    expect(report.status).toBe('not-installed')
    expect(report.ok).toBe(false)
  })

  it('skips the object diff on a version mismatch, and does NOT report ok', () => {
    const report = diffSurface(
      expected,
      completeInstall(expected, {
        installedVersion: '3.0.0',
        // Even with everything missing, a different version must not produce
        // object-level damage — the pinned bundle is the wrong manifest.
        presentOperators: new Set(),
        functionSignatures: new Map(),
      }),
    )
    expect(report.status).toBe('version-mismatch')
    // Nothing was verified, so `ok` must be false — a `verify || fail` gate
    // must not pass on an install the command could not actually check.
    expect(report.ok).toBe(false)
    expect(report.counts).toBeNull()
    expect(report.findings).toHaveLength(1)
    expect(report.findings[0].message).toContain('stash eql upgrade')
  })

  it('treats a missing version() on a present schema as damage', () => {
    const report = diffSurface(
      expected,
      completeInstall(expected, { installedVersion: null }),
    )
    expect(report.status).toBe('incomplete')
    const finding = report.findings.find((f) => f.kind === 'version')
    expect(finding?.severity).toBe('damage')
  })

  it('treats missing pgcrypto as damage', () => {
    const report = diffSurface(
      expected,
      completeInstall(expected, {
        pgcryptoInstalled: false,
        pgcryptoSchema: null,
      }),
    )
    expect(report.status).toBe('incomplete')
    expect(report.findings.some((f) => f.kind === 'extension')).toBe(true)
  })

  it('treats pgcrypto relocated off the EQL search_path as damage', () => {
    // Presence alone is not enough — the EQL functions pin
    // `search_path = pg_catalog, extensions, public`, so a pgcrypto in any
    // other schema fails at runtime (same rule as the install preflight).
    const report = diffSurface(
      expected,
      completeInstall(expected, { pgcryptoSchema: 'crypto_tools' }),
    )
    expect(report.status).toBe('incomplete')
    const finding = report.findings.find((f) => f.kind === 'extension')
    expect(finding?.severity).toBe('damage')
    expect(finding?.message).toContain('crypto_tools')
    expect(finding?.message).toContain('ALTER EXTENSION pgcrypto SET SCHEMA')
  })
})
