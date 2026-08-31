/**
 * `@cipherstash/stack-supabase` declares no `browser` export condition (#804).
 *
 * The sibling of `packages/stack/__tests__/browser-export-condition.test.ts`,
 * and it exists because this package has a `wasm-inline` entry of its own.
 * `./wasm-inline` binds the WASM engine from `@cipherstash/stack/wasm-inline`,
 * and that engine's core requires `clientKey` — a workspace secret — on every
 * auth path, OIDC federation included. So the entry is edge-safe and NOT
 * browser-safe, which is what the note at the bottom of `src/wasm-inline.ts`
 * says ("it is not browser-safe (#804)"). Nothing enforced it here: the two
 * facts a bundler complaint would tempt someone to reconcile — an ESM-only,
 * native-free entry that nonetheless must not reach a browser — sit in
 * different files.
 *
 * Separate from `wasm-entry-edge-safety.test.ts`, which asserts the same
 * entry's EDGE safety by scanning the emitted bundle and therefore skips when
 * `dist/` is absent. This one reads the manifest, so it must not skip: a
 * `browser` condition is wrong whether or not anyone has built the package.
 */

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

describe('@cipherstash/stack-supabase declares no browser build (#804)', () => {
  it('has no `browser` export condition on any subpath', () => {
    const packageJson = JSON.parse(
      readFileSync(
        path.resolve(fileURLToPath(import.meta.url), '../../package.json'),
        'utf8',
      ),
    ) as { browser?: unknown; exports: Record<string, unknown> }

    expect(packageJson.browser).toBeUndefined()
    expect(JSON.stringify(packageJson.exports)).not.toContain('"browser"')
  })
})
