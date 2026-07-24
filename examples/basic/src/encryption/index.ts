import { Encryption } from '@cipherstash/stack/v3'
import { extractEncryptionSchema, types } from '@cipherstash/stack-drizzle'
import { integer, pgTable, timestamp } from 'drizzle-orm/pg-core'

// EQL v3 encrypted columns are concrete Postgres domains built with the
// `types.*` factories. The domain fixes the query capabilities: `TextSearch`
// is equality + order/range + free-text, the v3 equivalent of what the old v2
// builder spelled `.equality().freeTextSearch()`.
export const usersTable = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: types.TextSearch('email'),
  name: types.TextSearch('name'),
  createdAt: timestamp('created_at').defaultNow(),
})

const usersSchema = extractEncryptionSchema(usersTable)

export const encryptionClient = await Encryption({
  schemas: [usersSchema],
})
