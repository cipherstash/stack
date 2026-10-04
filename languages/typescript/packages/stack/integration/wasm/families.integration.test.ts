/**
 * The full v3 family matrix over the WASM entry (#662): every covered domain,
 * every capability-derived positive and negative op, real ZeroKMS encryption
 * and real rows in a real Postgres — the same suite the Drizzle and Supabase
 * adapters run, driven through `@cipherstash/stack/wasm-inline`'s
 * encrypt/encryptQuery/encryptQueryBulk plus the documented raw-SQL casts.
 */
import { FAMILY_NAMES } from '@cipherstash/test-kit'
import { runFamilySuite } from '@cipherstash/test-kit/suite'
import { makeWasmAdapter } from './adapter'

for (const family of FAMILY_NAMES) {
  runFamilySuite(family, makeWasmAdapter)
}
