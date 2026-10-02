/**
 * Binds `__fixtures__/scaffold/*.ts` to what `generatePlaceholderClient`
 * actually emits.
 *
 * The fixtures are the only thing in the repo that COMPILES the file
 * `stash init` writes into a user's project — `tsconfig.scaffold.json` and the
 * CI step that runs it exist for that. But a typechecked fixture is worthless
 * if the generator can drift away from it, and the existing codegen tests only
 * `toContain`-match fragments while `build-schema.test.ts` stubs the generator
 * out entirely. That combination is how `Encryption({ schemas: [] })` shipped:
 * every test was green and no compiler ever saw the output (#772 review,
 * finding 6).
 *
 * So: byte-for-byte, both directions. Change a template, regenerate the
 * fixture; the compiler then has an opinion about it.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { PLACEHOLDER_TABLE_NAME } from '@/config/index.js'
import { generatePlaceholderClient } from '../utils.js'

const FIXTURE_DIR = path.resolve(
  fileURLToPath(import.meta.url),
  '../../../../../__fixtures__/scaffold',
)

const fixture = (name: string) =>
  readFileSync(path.join(FIXTURE_DIR, name), 'utf-8')

describe('the scaffolded client fixtures match the generator', () => {
  // Named `.generated.ts` so biome.json's existing exclusion leaves them alone:
  // they are template OUTPUT, and reformatting them would break the byte-for-byte
  // comparison below (which is the only thing tying the compiler to the generator).
  it.each([
    ['generic.generated.ts', 'postgresql'],
    ['drizzle.generated.ts', 'drizzle'],
  ] as const)('%s', (file, integration) => {
    expect(fixture(file)).toBe(generatePlaceholderClient(integration))
  })

  // `supabase` shares the generic template; pin that so a future split does not
  // silently leave the supabase path ungated.
  it('supabase reuses the generic template', () => {
    expect(generatePlaceholderClient('supabase')).toBe(
      fixture('generic.generated.ts'),
    )
  })
})

describe('the scaffold compiles because it declares a table', () => {
  it.each(['generic.generated.ts', 'drizzle.generated.ts'])(
    '%s passes a non-empty schema set',
    (file) => {
      const body = fixture(file)
      // The empty form is a hard TS2769 against both overloads — `Encryption`
      // requires at least one table by design (S-6), so the scaffold cannot go
      // back to `schemas: []` without breaking every project it is written into.
      expect(body).not.toContain('Encryption({ schemas: [] })')
      expect(body).toContain('schemas: [placeholderTable]')
    },
  )

  it.each(['generic.generated.ts', 'drizzle.generated.ts'])(
    '%s uses the sentinel name the config loader refuses',
    (file) => {
      // `loadEncryptConfig` exits 1 when this is the only table left, so the
      // two must agree — otherwise the user gets a confusing "table not found"
      // from whichever command runs next instead of "you never replaced this".
      expect(fixture(file)).toContain(`'${PLACEHOLDER_TABLE_NAME}'`)
    },
  )
})
