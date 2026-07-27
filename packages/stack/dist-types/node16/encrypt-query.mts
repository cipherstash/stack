/**
 * The ESM declaration surface under NODE16 resolution — `import` → `*.d.ts`.
 *
 * `../encrypt-query.ts` already covers the `.d.ts` set, but through a relative
 * path under `moduleResolution: bundler`. That combination cannot catch a broken
 * `exports` map, a missing `types` condition, or a subpath that resolves under a
 * bundler but not under Node's own algorithm — the resolution mode most server
 * consumers actually use.
 *
 * Same assertions as the `.cts` twin; the only difference is which condition the
 * resolver takes, which is exactly what is under test.
 */

import type {
  EncryptedTextSearchColumn,
  PlaintextForColumn,
  QueryTypesForColumn,
} from '@cipherstash/stack/eql/v3'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'

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

// The domain carrier that makes the inference above possible must not be part
// of the public surface. There is no `stripInternal` in this build, so a plainly
// named property would be reachable here — typed `D | undefined`, and always
// `undefined` at runtime. Keyed by a non-exported `unique symbol`, it is not.
// @ts-expect-error - the phantom domain carrier is not nameable by consumers
void users.email.__domain

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
