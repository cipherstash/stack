/**
 * Seed + oracle helpers for the EQL v3 String e2e matrix. Ported from
 * `packages/drizzle/__tests__/fixtures/eql-v3-seed-data.ts`.
 *
 * Each row sets email = bio = name = label, so a single label drives all three
 * index columns (email: text_eq, bio: text_match, name: text_ord) and the oracles
 * below predict the expected matching ids per operator.
 */

export interface V3SeedRow {
  readonly id: string
  readonly label: string
}

// Lexicographic spread for ord; shared-trigram pair (aardvark/aard) for match.
export const v3Seed: ReadonlyArray<V3SeedRow> = [
  { id: 'e2e-strv3-0', label: 'aardvark' },
  { id: 'e2e-strv3-1', label: 'aard' },
  { id: 'e2e-strv3-2', label: 'banana' },
  { id: 'e2e-strv3-3', label: 'cherry' },
  { id: 'e2e-strv3-4', label: 'date' },
]

const ids = (rows: ReadonlyArray<V3SeedRow>) => rows.map((r) => r.id).sort()

export const oracleEq = (target: string) => ids(v3Seed.filter((r) => r.label === target))
export const oracleNe = (target: string) => ids(v3Seed.filter((r) => r.label !== target))
export const oracleContains = (sub: string) => ids(v3Seed.filter((r) => r.label.includes(sub)))
export const oracleLt = (target: string) => ids(v3Seed.filter((r) => r.label < target))
export const oracleLte = (target: string) => ids(v3Seed.filter((r) => r.label <= target))
export const oracleGt = (target: string) => ids(v3Seed.filter((r) => r.label > target))
export const oracleBetween = (lo: string, hi: string) =>
  ids(v3Seed.filter((r) => r.label >= lo && r.label <= hi))
export const oracleInArray = (targets: ReadonlyArray<string>) =>
  ids(v3Seed.filter((r) => targets.includes(r.label)))
