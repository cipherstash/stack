import { FAMILY_NAMES } from '@cipherstash/test-kit'
import { runFamilySuite } from '@cipherstash/test-kit/suite'
import { makeDrizzleAdapter } from './adapter'

/**
 * Every EQL v3 domain the SDK models, driven through the Drizzle adapter against
 * real ZeroKMS ciphertext — the same catalog, oracle and driver as the Supabase
 * suite, so the two cannot claim different coverage.
 */
for (const family of FAMILY_NAMES) {
  runFamilySuite(family, makeDrizzleAdapter)
}
