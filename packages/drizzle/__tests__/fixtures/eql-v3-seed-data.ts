export type V3SeedRow = { label: string }

/** Lexicographic spread for ord; shared-trigram pair (aardvark/aard) for match. */
export const v3SeedData: V3SeedRow[] = [
  { label: 'aardvark' },
  { label: 'aard' },
  { label: 'banana' },
  { label: 'cherry' },
  { label: 'date' },
]

export function oracleEq(target: string): V3SeedRow[] {
  return v3SeedData.filter((r) => r.label === target)
}
export function oracleNe(target: string): V3SeedRow[] {
  return v3SeedData.filter((r) => r.label !== target)
}
export function oracleContains(sub: string): V3SeedRow[] {
  return v3SeedData.filter((r) => r.label.includes(sub))
}
export function oracleLt(target: string): V3SeedRow[] {
  return v3SeedData.filter((r) => r.label < target)
}
export function oracleAscLabels(): string[] {
  return [...v3SeedData]
    .sort((a, b) => a.label.localeCompare(b.label))
    .map((r) => r.label)
}
