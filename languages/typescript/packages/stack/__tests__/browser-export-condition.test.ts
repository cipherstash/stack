/**
 * `@cipherstash/stack` declares no `browser` export condition (#804).
 *
 * The consequence of the WASM core's credential contract, and the one part of
 * it a reader can undo by accident. The core requires `clientId` AND
 * `clientKey` on EVERY auth path — including OIDC federation, the arm that
 * exists so a caller never handles a workspace secret — so
 * `@cipherstash/stack/wasm-inline` is not browser-safe. That contract is
 * asserted against the real core in
 * `__tests__/wasm-inline-core-credential-contract.test.ts`; this file asserts
 * the packaging that follows from it.
 *
 * `src/wasm-inline.ts` tells callers there is no `browser` condition and
 * explains why. Nothing enforced it, so adding one to quiet a bundler
 * complaint would ship a workspace secret to the browser and leave that
 * doc silently wrong.
 *
 * WHY IT LIVES HERE and not with the contract file. It reads a manifest. It
 * needs no WASM build, no credentials and no database, so it belongs in the
 * suite every contributor runs. The contract file needs wasm-pack output that
 * `pnpm install` does not produce, which is why it is excluded from
 * `vitest.config.ts` and run by one CI job — and while this assertion lived
 * inside it, it was checked by no local `pnpm --filter @cipherstash/stack
 * test`, and on a fork PR by nothing at all (`wasm-e2e-tests` and `run-tests`
 * both hard-fail at `require-cs-secrets` there; `lint` runs only Biome).
 * `scripts/__tests__/wasm-core-contract-ci.test.mjs` holds it in the default
 * suite.
 *
 * Same rule as the contract file: if the core stops requiring `clientKey`,
 * come back through #804 — don't just delete this. The `browser` export
 * condition (#805), a live browser smoke test and browser guidance in
 * `skills/stash-supabase/SKILL.md` are all blocked on that and nothing else.
 */

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

describe('@cipherstash/stack declares no browser build (#804)', () => {
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
