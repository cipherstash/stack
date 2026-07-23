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
  // Longest specifiers first: Vite alias keys are prefix-matched in order.
  '@cipherstash/test-kit/json-suite': resolve(
    repoRoot,
    'packages/test-kit/src/run-json-suite.ts',
  ),
  '@cipherstash/test-kit/suite': resolve(
    repoRoot,
    'packages/test-kit/src/run-family-suite.ts',
  ),
  '@cipherstash/test-kit/catalog': resolve(
    repoRoot,
    'packages/test-kit/src/catalog.ts',
  ),
  '@cipherstash/test-kit/integration-clerk': resolve(
    repoRoot,
    'packages/test-kit/src/integration/clerk.ts',
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
  // The core↔adapter seam, consumed by the split adapter packages.
  '@cipherstash/stack/adapter-kit': resolve(
    repoRoot,
    'packages/stack/src/adapter-kit.ts',
  ),
  '@cipherstash/stack/encryption': resolve(
    repoRoot,
    'packages/stack/src/encryption/index.ts',
  ),
  '@cipherstash/stack/types': resolve(
    repoRoot,
    'packages/stack/src/types-public.ts',
  ),
  '@cipherstash/stack/errors': resolve(
    repoRoot,
    'packages/stack/src/errors/index.ts',
  ),
  '@cipherstash/stack/identity': resolve(
    repoRoot,
    'packages/stack/src/identity/index.ts',
  ),
  // The Supabase adapter now lives in its own package (was
  // `@cipherstash/stack/supabase`); resolve it to source too.
  '@cipherstash/stack-supabase': resolve(
    repoRoot,
    'packages/stack-supabase/src/index.ts',
  ),
  // The Drizzle adapter package (was `@cipherstash/stack/drizzle` +
  // `@cipherstash/stack/eql/v3/drizzle`). Root only: the `./v3` subpath
  // collapsed into it, so there is no longer a longer prefix to order first.
  '@cipherstash/stack-drizzle': resolve(
    repoRoot,
    'packages/stack-drizzle/src/index.ts',
  ),
  // Bare entry LAST: it is a prefix of every subpath above, and Vite matches in
  // order, so the subpaths must win first. Both sibling tsconfigs map bare
  // `@cipherstash/stack` → `src/index.ts`; without the runtime match here a
  // consumer importing the bare specifier would fall through to
  // `packages/stack/dist`, re-coupling `pnpm test` to a prior `pnpm build`.
  '@cipherstash/stack': resolve(repoRoot, 'packages/stack/src/index.ts'),
}

/**
 * The aliases needed to load stack's SOURCE (not just its public subpaths) from a
 * vitest config: stack's own internal `@/` alias — which its source uses and which
 * therefore leaks into any package that source-resolves it — plus the wasm-inline
 * stubs for the two `/wasm-inline` subpaths Vitest cannot resolve. All resolve to
 * fixed locations under `packages/stack`, so they are shared here rather than
 * copy-pasted into every package's vitest config.
 *
 * Spread AFTER `sharedAlias`: `resolve: { alias: { ...sharedAlias, ...stackSourceAlias } }`.
 */
export const stackSourceAlias: Record<string, string> = {
  '@/': `${resolve(repoRoot, 'packages/stack/src')}/`,
  '@cipherstash/protect-ffi/wasm-inline': resolve(
    repoRoot,
    'packages/stack/__tests__/helpers/stub-protect-ffi-wasm-inline.ts',
  ),
  '@cipherstash/auth/wasm-inline': resolve(
    repoRoot,
    'packages/stack/__tests__/helpers/stub-auth-wasm-inline.ts',
  ),
}
