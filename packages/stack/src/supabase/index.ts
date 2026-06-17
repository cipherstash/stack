import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import { EncryptedQueryBuilderImpl } from './query-builder'
import type {
  EncryptedSupabaseConfig,
  EncryptedSupabaseInstance,
} from './types'

/**
 * Create an encrypted Supabase wrapper that transparently handles encryption
 * and decryption for queries on encrypted columns.
 *
 * @param config - Configuration containing the encryption client and Supabase client.
 * @returns An object with a `from()` method that mirrors `supabase.from()` but
 *   auto-encrypts mutations, adds `::jsonb` casts, encrypts filter values, and
 *   decrypts results.
 *
 * @example
 * ```typescript
 * import { Encryption } from '@cipherstash/stack'
 * import { encryptedSupabase } from '@cipherstash/stack/supabase'
 * import { encryptedTable, encryptedColumn } from '@cipherstash/stack/schema'
 *
 * const users = encryptedTable('users', {
 *   name: encryptedColumn('name').freeTextSearch().equality(),
 *   email: encryptedColumn('email').freeTextSearch().equality(),
 * })
 *
 * const client = await Encryption({ schemas: [users] })
 * const eSupabase = encryptedSupabase({ encryptionClient: client, supabaseClient: supabase })
 *
 * // INSERT - auto-encrypts, auto-converts to PG composite
 * await eSupabase.from('users', users)
 *   .insert({ name: 'John', email: 'john@example.com', age: 30 })
 *
 * // SELECT with filter - auto-casts ::jsonb, auto-encrypts search term, auto-decrypts
 * const { data } = await eSupabase.from('users', users)
 *   .select('id, email, name')
 *   .eq('email', 'john@example.com')
 * ```
 */
export function encryptedSupabase(
  config: EncryptedSupabaseConfig,
): EncryptedSupabaseInstance {
  const { encryptionClient, supabaseClient } = config

  return {
    from<T extends Record<string, unknown> = Record<string, unknown>>(
      tableName: string,
      schema: EncryptedTable<EncryptedTableColumn>,
    ) {
      return new EncryptedQueryBuilderImpl<T>(
        tableName,
        schema,
        encryptionClient,
        supabaseClient,
      )
    },
  }
}

export type {
  EncryptedQueryBuilder,
  EncryptedSupabaseConfig,
  EncryptedSupabaseError,
  EncryptedSupabaseInstance,
  EncryptedSupabaseResponse,
  PendingOrCondition,
  SupabaseClientLike,
} from './types'
