/**
 * CipherStash encryption client — placeholder.
 *
 * `stash init` wrote this file. It is intentionally NOT a real Drizzle
 * schema. Your existing schema files (typically under `src/db/`) remain
 * authoritative — your agent will edit those directly when you encrypt a
 * column, then update the `Encryption({ schemas: [...] })` call below
 * to reference the encrypted tables you declared there.
 *
 * Until that happens, the encryption client is initialised with a single
 * placeholder table so that this file compiles, and `stash eql validate` and
 * `stash encrypt backfill` refuse to run and point back here. (`stash
 * encrypt drop` resolves against the database and never reads this file.)
 *
 * This project uses EQL v3. Encrypted columns are concrete Postgres domains
 * built with the `types.*` factories from `@cipherstash/stack-drizzle`.
 * Each domain's query capabilities are FIXED by the type you pick — there is
 * no capability config object. Choose the factory whose capabilities you need:
 *   types.Text / types.Integer / …     storage only (encrypt/decrypt, no queries)
 *   types.TextEq / types.IntegerEq     equality (eq, inArray)
 *   types.IntegerOrd / types.DateOrd   equality + order/range (gt/lt/between/sort)
 *   types.TextMatch                    free-text match only
 *   types.TextSearch                   equality + order/range + free-text
 *   types.Json                         encrypted-JSONB containment + selectors
 *
 * Order columns with the `*Ord` factories above, not `*OrdOre`. The ORE
 * flavour needs a Postgres operator class that only a privileged role can
 * create — where the install could not create it, the EQL bundle poisons every
 * `_ord_ore` domain, and each write to one fails a CHECK. `*Ord` orders and
 * indexes on any role. `stash eql status` reports which case this database
 * is in.
 *
 * --- Pattern reference (copy into your real schema, do NOT use as-is) ---
 *
 * Encrypted twin column for an existing populated column (path 3 — lifecycle):
 *
 *   import { pgTable, integer, text } from 'drizzle-orm/pg-core'
 *   import { types } from '@cipherstash/stack-drizzle'
 *
 *   export const users = pgTable('users', {
 *     id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
 *     email: text('email').notNull(),                        // existing plaintext, unchanged for now
 *     email_encrypted: types.TextSearch('email_encrypted'),  // encrypted twin, NULLABLE — never .notNull()
 *   })
 *
 * Net-new encrypted column (path 1 — declare encrypted from the start):
 *
 *   export const orders = pgTable('orders', {
 *     id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
 *     billing_address: types.TextEq('billing_address'),
 *   })
 *
 * Once you have encrypted tables declared, harvest them and pass to Encryption():
 *
 *   import { extractEncryptionSchema } from '@cipherstash/stack-drizzle'
 *   import { Encryption } from '@cipherstash/stack/v3'
 *   import { users, orders } from './db/schema'
 *
 *   export const encryptionClient = await Encryption({
 *     schemas: [extractEncryptionSchema(users), extractEncryptionSchema(orders)],
 *   })
 */
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'

// REPLACE THIS. It exists only so this file compiles before you have declared
// any encrypted tables — `Encryption` requires at least one. Swap it for your
// real tables (see the patterns above); `stash eql validate` and `stash
// encrypt backfill` refuse to run while the placeholder is still here.
export const placeholderTable = encryptedTable('__stash_placeholder__', {
  replace_me: types.Text('replace_me'),
})

export const encryptionClient = await Encryption({ schemas: [placeholderTable] })
