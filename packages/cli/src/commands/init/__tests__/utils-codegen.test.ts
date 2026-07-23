import { describe, expect, it } from 'vitest'
import type { SchemaDef } from '../types.js'
import { generateClientFromSchemas } from '../utils.js'

const schemas: SchemaDef[] = [
  {
    tableName: 'users',
    columns: [
      { name: 'email', domain: 'TextSearch' },
      { name: 'age', domain: 'IntegerOrd' },
      { name: 'verified', domain: 'Boolean' },
    ],
  },
]

describe('generateClientFromSchemas', () => {
  it('emits the chosen v3 domain factory per column (generic/postgresql)', () => {
    const out = generateClientFromSchemas('postgresql', schemas)
    expect(out).toContain("email: types.TextSearch('email'),")
    expect(out).toContain("age: types.IntegerOrd('age'),")
    expect(out).toContain("verified: types.Boolean('verified'),")
    expect(out).toContain("from '@cipherstash/stack/v3'")
    expect(out).toContain('EncryptionV3(')
  })

  it('emits the chosen v3 domain factory per column (drizzle)', () => {
    const out = generateClientFromSchemas('drizzle', schemas)
    expect(out).toContain("email: types.TextSearch('email'),")
    expect(out).toContain("age: types.IntegerOrd('age'),")
    // The collapsed root: `@cipherstash/stack-drizzle` dropped its EQL v2
    // surface and folded `./v3` into `.`, de-suffixing the exports. The
    // negatives matter as much as the positives — this string is written into
    // the user's repo as real source, and nothing type-checks a template
    // literal, so the removed names can only be caught here.
    expect(out).toContain('extractEncryptionSchema(')
    expect(out).toContain("from '@cipherstash/stack-drizzle'")
    expect(out).not.toContain('extractEncryptionSchemaV3')
    expect(out).not.toContain('@cipherstash/stack-drizzle/v3')
  })

  it('carries no residual v2 capability vocabulary', () => {
    const generic = generateClientFromSchemas('postgresql', schemas)
    const drizzle = generateClientFromSchemas('drizzle', schemas)
    for (const out of [generic, drizzle]) {
      expect(out).not.toMatch(/searchOps/)
      expect(out).not.toMatch(/freeTextSearch|orderAndRange|\.equality\(/)
    }
  })

  it('routes supabase through the generic generator, not drizzle', () => {
    // `supabase` and `postgresql` share generateGenericFromSchemas; a misroute
    // (dropping the `case 'supabase':` fallthrough, or routing it to drizzle)
    // is otherwise uncovered — the other cases only exercise postgresql/drizzle.
    const out = generateClientFromSchemas('supabase', schemas)
    expect(out).toContain("email: types.TextSearch('email'),")
    expect(out).toContain("from '@cipherstash/stack/v3'")
    expect(out).not.toContain('@cipherstash/stack-drizzle')
  })

  it('throws for prisma-next instead of returning an undefined client', () => {
    // prisma-next is unreachable from schema/build.ts, but the switch must stay
    // total: fail loudly rather than silently returning undefined (which would
    // write a broken client file) if a caller ever routes it here.
    expect(() => generateClientFromSchemas('prisma-next', schemas)).toThrow(
      /does not generate a prisma-next client/,
    )
  })
})

// Exhaustive round-trip over the closed V3Domain union: the sample fixtures
// above only exercise 3 of 13 domains, so every domain is proven to emit
// verbatim through both generators. `V3Domain` and `DataType` are finite closed
// unions, so enumeration is complete — a fast-check property would sample the
// same finite set and add nothing (and `packages/cli` has no fast-check dep).
const ALL_DOMAINS: import('../types.js').V3Domain[] = [
  'Text',
  'TextEq',
  'TextOrd',
  'TextMatch',
  'TextSearch',
  'Integer',
  'IntegerEq',
  'IntegerOrd',
  'Date',
  'DateEq',
  'DateOrd',
  'Boolean',
  'Json',
]

describe.each([
  'postgresql',
  'drizzle',
] as const)('generateClientFromSchemas domain round-trip (%s)', (integration) => {
  it.each(ALL_DOMAINS)('emits types.%s verbatim', (domain) => {
    const s: SchemaDef[] = [
      { tableName: 'x', columns: [{ name: 'c', domain }] },
    ]
    expect(generateClientFromSchemas(integration, s)).toContain(
      `c: types.${domain}('c'),`,
    )
  })
})
