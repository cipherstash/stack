import { describe, expect, it } from 'vitest'
import type { SchemaDef } from '../types.js'
import {
  generateClientFromSchemas,
  generatePlaceholderClient,
} from '../utils.js'

// `stash init --drizzle` writes these strings into the USER's repo as real
// source. Nothing type-checks a template literal, so a rename in
// `@cipherstash/stack-drizzle` cannot break the build here — it breaks the
// scaffolded project instead, in someone else's checkout.
//
// `utils-codegen.test.ts` covers the generated client's happy path. This file
// covers the surface that had no test at all — `generatePlaceholderClient`,
// whose doc block is a copy-paste reference the handoff agent works from — and
// asserts, for BOTH strings, that nothing removed with EQL v2 survives:
//   - the `@cipherstash/stack-drizzle/v3` specifier (`./v3` collapsed into `.`)
//   - `extractEncryptionSchemaV3` / `createEncryptionOperatorsV3`
//   - `encryptedType`, the v2 config-flag column factory

const SCHEMAS: SchemaDef[] = [
  {
    tableName: 'users',
    columns: [
      { name: 'email', domain: 'TextSearch' },
      { name: 'age', domain: 'IntegerOrd' },
    ],
  },
]

/** Every drizzle-flavoured string `stash init` can write into a user's repo. */
const GENERATED_SOURCES: Array<[string, string]> = [
  ['generateClientFromSchemas', generateClientFromSchemas('drizzle', SCHEMAS)],
  ['generatePlaceholderClient', generatePlaceholderClient('drizzle')],
]

describe.each(
  GENERATED_SOURCES,
)('drizzle scaffold — %s', (_name, generated) => {
  it('names the drizzle package root, never the removed ./v3 subpath', () => {
    expect(generated).toContain('@cipherstash/stack-drizzle')
    expect(generated).not.toContain('@cipherstash/stack-drizzle/v3')
  })

  it('uses the de-suffixed export names, never the removed *V3 aliases', () => {
    expect(generated).not.toContain('extractEncryptionSchemaV3')
    expect(generated).not.toContain('createEncryptionOperatorsV3')
  })

  it('never scaffolds the removed EQL v2 authoring surface', () => {
    expect(generated).not.toContain('encryptedType')
    expect(generated).not.toContain('eql_v2_encrypted')
  })
})

describe('generatePlaceholderClient (drizzle)', () => {
  const placeholder = generatePlaceholderClient('drizzle')

  it('shows the harvest pattern with the collapsed root import', () => {
    expect(placeholder).toContain(
      "import { extractEncryptionSchema } from '@cipherstash/stack-drizzle'",
    )
    expect(placeholder).toContain('extractEncryptionSchema(users)')
  })
})
