/**
 * CipherStash encryption client — placeholder.
 *
 * `stash init` wrote this file. It is intentionally NOT a real schema
 * definition. Your existing schema files remain authoritative — your
 * agent will declare encrypted columns there and update the
 * `Encryption({ schemas: [...] })` call below to reference them.
 *
 * Until that happens, the encryption client is initialised with a single
 * placeholder table so that this file compiles, and `stash encrypt`
 * commands refuse to run and point back here.
 *
 * This project uses EQL v3. Encrypted columns are concrete Postgres domains
 * built with the `types.*` factories from `@cipherstash/stack/eql/v3`
 * (also re-exported from `@cipherstash/stack/v3`). Each domain's query
 * capabilities are FIXED by the type you pick — there is no chainable
 * capability tuner. Choose the factory whose capabilities you need:
 *   types.Text / types.Integer / …     storage only (encrypt/decrypt, no queries)
 *   types.TextEq / types.IntegerEq     equality
 *   types.IntegerOrd / types.DateOrd   equality + order/range
 *   types.TextMatch                    free-text match only
 *   types.TextSearch                   equality + order/range + free-text
 *   types.Json                         encrypted-JSONB containment + selectors
 *
 * --- Pattern reference (copy into your real schema, do NOT use as-is) ---
 *
 * Encrypted twin column for an existing populated column (path 3 — lifecycle):
 *
 *   import { encryptedTable, types } from '@cipherstash/stack/v3'
 *
 *   export const users = encryptedTable('users', {
 *     email_encrypted: types.TextSearch('email_encrypted'),
 *   })
 *
 * Net-new encrypted column (path 1 — declare encrypted from the start):
 *
 *   export const orders = encryptedTable('orders', {
 *     billing_address: types.TextEq('billing_address'),
 *   })
 *
 * Once you have encrypted tables declared, pass them to Encryption():
 *
 *   import { Encryption } from '@cipherstash/stack/v3'
 *   import { users, orders } from './db/schema'
 *
 *   export const encryptionClient = await Encryption({
 *     schemas: [users, orders],
 *   })
 */
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'

// REPLACE THIS. It exists only so this file compiles before you have declared
// any encrypted tables — `Encryption` requires at least one. Swap it for your
// real tables (see the patterns above); `stash encrypt` refuses to run while
// the placeholder is still here.
export const placeholderTable = encryptedTable('__stash_placeholder__', {
  replace_me: types.Text('replace_me'),
})

export const encryptionClient = await Encryption({ schemas: [placeholderTable] })
