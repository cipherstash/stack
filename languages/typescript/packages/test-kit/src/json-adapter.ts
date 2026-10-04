import type { JsonDocument } from '@cipherstash/stack/eql/v3'

export type JsonScalar = string | number | boolean

export type JsonQueryOp =
  | { readonly kind: 'contains'; readonly value: JsonDocument }
  | {
      readonly kind: 'selector'
      readonly comparison: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte'
      readonly path: string
      readonly value: unknown
    }
  | {
      readonly kind: 'selectorOrder'
      readonly path: string
      readonly direction: 'asc' | 'desc'
    }

export type JsonSeedRow = Readonly<{
  rowKey: string
  document: JsonDocument
}>

export type JsonTableSpec = Readonly<{
  name: string
  rows: readonly JsonSeedRow[]
}>

/**
 * Adapter seam for the shared encrypted-JSON integration suite.
 *
 * Drizzle and Prisma Next implement the same containment, selector-comparison,
 * and selector-ordering contract through their public surfaces. Supabase is
 * deliberately absent: EQL 3.0.2 typed JSON query operands cannot be expressed
 * through PostgREST, and its dedicated boundary suite asserts that rejection.
 */
export interface JsonIntegrationAdapter {
  readonly name: 'drizzle' | 'prisma-next'
  setup(table: JsonTableSpec): Promise<void>
  teardown(): Promise<void>
  run(op: JsonQueryOp): Promise<string[]>
}
