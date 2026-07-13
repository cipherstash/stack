import { types as v3Types } from '@cipherstash/stack/eql/v3'
import { makeEqlV3Column } from './column.js'

type V3Types = typeof v3Types

/**
 * Drizzle-native mirror of `@/eql/v3`'s `types` namespace. Each PascalCase
 * factory returns a Drizzle column wrapping the matching concrete v3 builder.
 */
export const types = Object.fromEntries(
  Object.entries(v3Types).map(([name, factory]) => [
    name,
    (columnName: string) => makeEqlV3Column(factory(columnName)),
  ]),
) as {
  [K in keyof V3Types]: (
    name: string,
  ) => ReturnType<typeof makeEqlV3Column<ReturnType<V3Types[K]>>>
}
