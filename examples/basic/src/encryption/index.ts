import { Encryption } from '@cipherstash/stack'
import {
  encryptedType,
  extractEncryptionSchema,
} from '@cipherstash/stack-drizzle'
import { integer, pgTable, timestamp } from 'drizzle-orm/pg-core'

export const usersTable = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: encryptedType<string>('email', {
    equality: true,
    freeTextSearch: true,
  }),
  name: encryptedType<string>('name', {
    equality: true,
    freeTextSearch: true,
  }),
  createdAt: timestamp('created_at').defaultNow(),
})

const usersSchema = extractEncryptionSchema(usersTable)

export const encryptionClient = await Encryption({
  schemas: [usersSchema],
})
