/**
 * Guards the auth-strategy re-exports from `@cipherstash/stack` — the PR's
 * headline "no separate `@cipherstash/auth` install" feature.
 *
 * The re-export in `src/index.ts` is a deliberate ESM workaround: a naive
 * `export { X } from '@cipherstash/auth'` resolves to `undefined`/throws under
 * real Node ESM (the CJS NAPI module's `module.exports = { ...native }` spread
 * defeats cjs-module-lexer). If that ever regresses, the names silently become
 * `undefined` and `OidcFederationStrategy.create(...)` blows up only at call
 * time, with nothing catching it at build/test. These tests assert each
 * strategy re-export resolves to the real auth binding.
 */

import auth from '@cipherstash/auth'
import { describe, expect, it } from 'vitest'
import * as stack from '@/index'

describe('@cipherstash/stack auth strategy re-exports', () => {
  it.each([
    'AccessKeyStrategy',
    'AutoStrategy',
    'DeviceSessionStrategy',
    'OidcFederationStrategy',
  ] as const)('re-exports %s as the real auth binding', (name) => {
    // biome-ignore lint/suspicious/noExplicitAny: dynamic key lookup
    const exported = (stack as any)[name]
    expect(exported, `${name} re-export is undefined`).toBeDefined()
    expect(typeof exported).toBe('function')
    // biome-ignore lint/suspicious/noExplicitAny: dynamic key lookup
    expect(exported).toBe((auth as any)[name])
  })
})
