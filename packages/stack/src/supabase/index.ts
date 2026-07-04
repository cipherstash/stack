import type { AnyV3Table, InferPlaintext } from '@/eql/v3'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import { EncryptedQueryBuilderImpl } from './query-builder'
import { EncryptedQueryBuilderV3Impl } from './query-builder-v3'
import type {
  EncryptedQueryBuilderV3,
  EncryptedSupabaseConfig,
  EncryptedSupabaseInstance,
  EncryptedSupabaseV3Config,
  EncryptedSupabaseV3Instance,
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

/**
 * Create an encrypted Supabase wrapper for **EQL v3** schemas — tables
 * authored with `@cipherstash/stack/eql/v3` whose columns are native
 * `eql_v3.*` domains.
 *
 * The public surface and call shape are identical to {@link encryptedSupabase}
 * (`.eq/.neq/.in/.gt/.gte/.lt/.lte/.like/.ilike/.match/.or/.not/.filter`,
 * `withLockContext`, `audit`); only the schema type and the wire encoding
 * differ. The same Supabase caveats carry over: the `eql_v3` schema must be
 * added to the project's **Exposed schemas** and granted to the Supabase
 * roles for the operators to resolve, and encrypted `ORDER BY` is
 * unsupported (range *filtering* works).
 *
 * @example
 * ```typescript
 * import { Encryption } from '@cipherstash/stack'
 * import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
 * import { encryptedSupabaseV3 } from '@cipherstash/stack/supabase'
 *
 * const users = encryptedTable('users', {
 *   email:  types.TextSearch('email'),  // eql_v3.text_search
 *   amount: types.Int4Ord('amount'),    // eql_v3.int4_ord
 * })
 *
 * const client = await Encryption({ schemas: [users] })
 * const es = encryptedSupabaseV3({ encryptionClient: client, supabaseClient: supabase })
 *
 * await es.from('users', users).insert({ email: 'a@b.com', amount: 30 })
 * await es.from('users', users).select('id, email, amount').eq('email', 'a@b.com')
 * await es.from('users', users).select('id, amount').gte('amount', 10).lte('amount', 100)
 * ```
 */
export function encryptedSupabaseV3(
  config: EncryptedSupabaseV3Config,
): EncryptedSupabaseV3Instance {
  const { encryptionClient, supabaseClient } = config

  return {
    from<
      Table extends AnyV3Table,
      Row extends Record<string, unknown> = InferPlaintext<Table>,
    >(tableName: string, table: Table) {
      return new EncryptedQueryBuilderV3Impl<Row>(
        tableName,
        table,
        encryptionClient,
        supabaseClient,
      ) as unknown as EncryptedQueryBuilderV3<Table, Row>
    },
  }
}

export type {
  EncryptedQueryBuilder,
  EncryptedQueryBuilderV3,
  EncryptedSupabaseConfig,
  EncryptedSupabaseError,
  EncryptedSupabaseInstance,
  EncryptedSupabaseResponse,
  EncryptedSupabaseV3Config,
  EncryptedSupabaseV3Instance,
  PendingOrCondition,
  SupabaseClientLike,
  V3FilterableKeys,
} from './types'
