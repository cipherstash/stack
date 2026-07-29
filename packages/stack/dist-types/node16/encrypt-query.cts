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
  AnyV3Table,
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

/**
 * The other two halves of the #815 criterion — schema-array shapes and config
 * typing — against the CJS declaration set.
 *
 * `../schemas-and-config.ts` asserts both, but only against the `.d.ts` pass
 * under bundler resolution. tsup emits `.d.cts` in a separate DTS pass, so a
 * divergence confined to it — in the `Encryption` overloads or in
 * `ClientConfig` — would ship green to every CJS consumer.
 */
export async function schemaAndConfigShapes() {
  const widened: AnyV3Table[] = [users]
  await Encryption({ schemas: widened })

  const frozen: readonly AnyV3Table[] = [users]
  await Encryption({ schemas: frozen })

  await Encryption({ schemas: [users].map((t) => t) })

  // @ts-expect-error - at least one table is required
  await Encryption({ schemas: [] })

  await Encryption({
    schemas: [users],
    // @ts-expect-error - `eqlVersion` was removed; Stack always authors EQL v3
    config: { eqlVersion: 2 },
  })

  // Excess-property checking only fires on fresh literals, so a shared config
  // const — what a v2 → v3 migration actually holds — used to compile and then
  // throw at runtime.
  const hoistedConfig = { workspaceCrn: 'crn', eqlVersion: 2 }
  await Encryption({
    schemas: [users],
    // @ts-expect-error - rejected even when the config is not a fresh literal
    config: hoistedConfig,
  })
}
