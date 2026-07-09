/**
 * v3 columns are `CREATE DOMAIN ... AS jsonb`, so they serialise as plain jsonb,
 * distinct from v2's composite-literal parser.
 */

export function v3ToDriver<TData>(value: TData): string | null {
  if (value === null || value === undefined) {
    return null
  }
  return JSON.stringify(value)
}

export function v3FromDriver<TData>(
  value: string | object | null | undefined,
): TData {
  if (value === null || value === undefined) {
    return value as TData
  }
  if (typeof value === 'object') {
    return value as TData
  }
  return JSON.parse(value) as TData
}
