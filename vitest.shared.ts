import { resolve } from 'node:path'

/**
 * Resolve `@cipherstash/test-kit` and the `@cipherstash/stack` public subpaths
 * it imports to SOURCE rather than `dist`.
 *
 * The kit has no build step, and its catalog imports stack through the public
 * subpaths (not stack's internal `@/` alias) because packages outside stack —
 * `@cipherstash/drizzle`, and the adapter packages after the split — have to be
 * able to import it too. Left unaliased, those specifiers resolve to
 * `packages/stack/dist`, which would couple `pnpm test` to a prior `pnpm build`.
 * The matching compile-time mapping is `packages/test-kit/tsconfig.json` `paths`.
 *
 * Spread into each package's vitest config rather than copied, so the two
 * cannot drift:
 *
 *     import { sharedAlias } from '../../vitest.shared'
 *     resolve: { alias: { ...sharedAlias, '@/': … } }
 */
const repoRoot = __dirname

export const sharedAlias: Record<string, string> = {
  '@cipherstash/test-kit/catalog': resolve(
    repoRoot,
    'packages/test-kit/src/catalog.ts',
  ),
  '@cipherstash/test-kit': resolve(repoRoot, 'packages/test-kit/src/index.ts'),
  '@cipherstash/stack/eql/v3': resolve(
    repoRoot,
    'packages/stack/src/eql/v3/index.ts',
  ),
  '@cipherstash/stack/schema': resolve(
    repoRoot,
    'packages/stack/src/schema/index.ts',
  ),
  '@cipherstash/stack/v3': resolve(
    repoRoot,
    'packages/stack/src/encryption/v3.ts',
  ),
  '@cipherstash/stack/supabase': resolve(
    repoRoot,
    'packages/stack/src/supabase/index.ts',
  ),
}
