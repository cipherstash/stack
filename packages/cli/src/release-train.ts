/**
 * The single source of truth for which packages ride this CLI's release train
 * — i.e. which packages `stash init` (and other guidance) must pin to the
 * versions this CLI release was built alongside (#661).
 *
 * Consumed from BOTH sides of the build boundary, which is the point:
 *
 * - `tsup.config.ts` iterates this map at build time to read each sibling
 *   workspace manifest and embed the versions (`__STASH_RUNTIME_VERSIONS__`).
 * - Runtime code (`install-deps.ts`) declares its integration-adapter
 *   packages against it, and a unit test asserts every adapter package is a
 *   key here — so adding a new adapter without adding it to the train FAILS
 *   the build's tests instead of silently installing unpinned and being
 *   exempt from the skew warning.
 *
 * Values are manifest paths relative to `packages/cli/`.
 */
export const RELEASE_TRAIN_MANIFESTS = {
  stash: './package.json',
  '@cipherstash/stack': '../stack/package.json',
  '@cipherstash/stack-drizzle': '../stack-drizzle/package.json',
  '@cipherstash/stack-supabase': '../stack-supabase/package.json',
  '@cipherstash/prisma-next': '../prisma-next/package.json',
  '@cipherstash/wizard': '../wizard/package.json',
} as const

export type ReleaseTrainPackage = keyof typeof RELEASE_TRAIN_MANIFESTS
