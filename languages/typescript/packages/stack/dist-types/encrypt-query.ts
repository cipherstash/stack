/**
 * Typed `encryptQuery` must be callable against the BUILT package.
 *
 * `PlaintextForColumn` / `QueryTypesForColumn` recover a column's domain with
 * `C extends EncryptedV3Column<infer D>`, which needs `D` to appear bare in the
 * instance type. Its only bare site in source is a PRIVATE field, and `tsc`
 * strips private member types on declaration emit — so in the published `.d.ts`
 * the inference fell back to the `V3DomainDefinition` constraint and every
 * derived helper collapsed. `QueryTypesForColumn` became `never`, which made
 * `QueryableColumnsOf` `never`, which typed the plaintext `never`:
 *
 *     client.encryptQuery('a@b.com', { table: users, column: users.email })
 *     // TS2345: Argument of type '"a@b.com"' is not assignable to type 'never'
 *
 * `encrypt` was unaffected (it resolves through `ColumnsOf`), so a smoke test
 * of the built types would have missed it. Assert the query path explicitly.
 */

import { Encryption, encryptedTable, types } from '../dist/encryption/v3.js'
import type {
  EncryptedTextSearchColumn,
  PlaintextForColumn,
  QueryTypesForColumn,
} from '../dist/eql/v3/index.js'

// The two helpers, on the concrete column class, straight from the emitted types.
const plaintext: string =
  null as unknown as PlaintextForColumn<EncryptedTextSearchColumn>
const queryTypes: 'equality' | 'orderAndRange' | 'freeTextSearch' =
  null as unknown as QueryTypesForColumn<EncryptedTextSearchColumn>
void plaintext
void queryTypes

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  age: types.IntegerOrd('age'),
})

export async function callable() {
  const client = await Encryption({ schemas: [users] })

  client.encrypt('a@b.com', { table: users, column: users.email })
  client.encryptQuery('a@b.com', {
    table: users,
    column: users.email,
    queryType: 'freeTextSearch',
  })
  client.encryptQuery(30, {
    table: users,
    column: users.age,
    queryType: 'orderAndRange',
  })

  // The narrowing must survive emit too, or the assertions above pass
  // vacuously. Each directive sits on the exact line the error is reported at —
  // `@ts-expect-error` only covers the following line, and the formatter is free
  // to split these calls across several.
  client.encryptQuery(
    // @ts-expect-error - `email` is a text domain, so the plaintext is a string
    123,
    { table: users, column: users.email },
  )
  client.encryptQuery('x', {
    table: users,
    column: users.email,
    // @ts-expect-error - `searchableJson` is not a capability of text_search
    queryType: 'searchableJson',
  })
}
