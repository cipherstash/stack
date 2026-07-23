import { describe, expect, it } from 'vitest'
import type { SchemaDef } from '../types.js'
import {
  generateClientFromSchemas,
  generatePlaceholderClient,
} from '../utils.js'

// `stash init --drizzle` writes these strings into the USER's repo as real
// source. Nothing type-checks a template literal, so a rename in
// `@cipherstash/stack-drizzle` cannot break the build here — it breaks the
// scaffolded project instead, in someone else's checkout. These assertions are
// the only thing standing between a de-suffixed export and a broken `stash
// init`.
//
// Pinned by this suite (all three removed when `./v3` collapsed into the root):
//   - the `@cipherstash/stack-drizzle/v3` specifier
//   - `extractEncryptionSchemaV3`
//   - `createEncryptionOperatorsV3`

const SCHEMAS: SchemaDef[] = [
  {
    tableName: 'users',
    columns: [
      { name: 'email', dataType: 'string', searchOps: ['equality'] },
      { name: 'age', dataType: 'number', searchOps: ['orderAndRange'] },
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
  it('imports the drizzle surface from the package ROOT, never the removed ./v3 subpath', () => {
    expect(generated).not.toContain('@cipherstash/stack-drizzle/v3')
    expect(generated).toContain('@cipherstash/stack-drizzle')
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

describe('generateClientFromSchemas (drizzle)', () => {
  const generated = generateClientFromSchemas('drizzle', SCHEMAS)

  it('names extractEncryptionSchema in both the import and the call site', () => {
    expect(generated).toContain(
      "import { types, extractEncryptionSchema } from '@cipherstash/stack-drizzle'",
    )
    expect(generated).toContain('extractEncryptionSchema(usersTable)')
  })
})
