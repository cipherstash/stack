import { FAMILY_NAMES } from '@cipherstash/test-kit'
import { runFamilySuite } from '@cipherstash/test-kit/suite'
import { makePrismaNextAdapter } from './adapter'

/**
 * Every EQL v3 domain the SDK models, driven through the prisma-next adapter
 * against real ZeroKMS ciphertext — the same catalog, oracle and driver as the
 * Drizzle and Supabase suites, so the three cannot claim different coverage.
 */
for (const family of FAMILY_NAMES) {
  runFamilySuite(family, makePrismaNextAdapter)
}
