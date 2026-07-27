/**
 * The CommonJS declaration surface — `require` → `dist/**\/*.d.cts`.
 *
 * The sibling `../encrypt-query.ts` gate reaches into `../dist/*.js` by relative
 * path under `moduleResolution: bundler`, so it never consults the `exports`
 * map and only ever sees the ESM `.d.ts` set. tsup emits the `.d.cts` set in a
 * separate pass, and `package.json` routes `require` at it. A defect confined to
 * that pass would ship to every CJS consumer with nothing here to catch it.
 *
 * This file is `.cts`, so TypeScript treats it as CommonJS and resolves
 * `@cipherstash/stack/v3` through the `require` condition. Importing BY PACKAGE
 * NAME (Node self-reference, which works because `package.json` has both a
 * `name` and an `exports` map) is the point: it exercises the conditions a
 * customer's resolver walks, not a path we happen to know.
 */

import type {
  EncryptedTextSearchColumn,
  PlaintextForColumn,
  QueryTypesForColumn,
} from '@cipherstash/stack/eql/v3'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'

// The two helpers, on the concrete column class, straight from the emitted
// `.d.cts`. These collapse to `never` / a wide union if the domain parameter is
// not recoverable after declaration emit.
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
  // vacuously. Each directive sits on the exact line the error is reported at.
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
