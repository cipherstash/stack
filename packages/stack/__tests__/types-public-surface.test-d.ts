import { describe, expectTypeOf, it } from 'vitest'
// Regression guard for the public `@cipherstash/stack/types` entrypoint
// (src/types-public.ts). The structural builder contracts and the
// `encryptModel` / `bulkEncryptModels` return-type mapper appear in PUBLIC
// return positions (encryption/index.ts), so consumers must be able to NAME
// them from the public path. Importing a member that is not re-exported fails
// typecheck — so this file compiling green proves the surface is complete.
import type {
  BuildableColumn,
  BuildableQueryColumn,
  BuildableTable,
  BuildableTableColumns,
  BuildableV3QueryableColumn,
  Encrypted,
  EncryptedFromBuildableTable,
} from '@/types-public'

describe('public @cipherstash/stack/types surface', () => {
  it('exposes the structural builder contracts', () => {
    // A v3 queryable column IS a BuildableColumn (interface extension).
    expectTypeOf<BuildableV3QueryableColumn>().toMatchTypeOf<BuildableColumn>()
    // The query-column union is nameable and non-trivial.
    expectTypeOf<BuildableQueryColumn>().not.toBeNever()
    // The client table contract is nameable.
    expectTypeOf<BuildableTable['tableName']>().toBeString()
  })

  it('exposes EncryptedFromBuildableTable (the encryptModel return mapper)', () => {
    interface Users extends BuildableTable {
      readonly _columnType: { email: unknown }
    }
    type Row = { id: number; email: string }
    type Enc = EncryptedFromBuildableTable<Row, Users>

    // Schema-column fields become Encrypted; passthrough fields keep their type.
    expectTypeOf<Enc['email']>().toEqualTypeOf<Encrypted>()
    expectTypeOf<Enc['id']>().toEqualTypeOf<number>()

    // The column-map helper is nameable too.
    expectTypeOf<keyof BuildableTableColumns<Users>>().toEqualTypeOf<'email'>()
  })
})
