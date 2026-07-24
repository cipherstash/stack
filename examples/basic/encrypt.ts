import 'dotenv/config'

import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'

// EQL v3: a column's query capabilities are fixed by the domain you pick —
// there are no chainable capability tuners. `types.Text` is storage-only
// (encrypt/decrypt, no queries), which is all this demo needs. Reach for
// `types.TextEq` / `types.TextSearch` when you need to query the column.
export const users = encryptedTable('users', {
  name: types.Text('name'),
})

export const client = await Encryption({
  schemas: [users],
})
