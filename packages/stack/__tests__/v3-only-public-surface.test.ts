import { describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import {
  createEncryptionClient,
  encryptedTable,
  types,
} from '@/encryption/client-v3'
import * as v3 from '@/encryption/v3'
import * as root from '@/index'
import * as schema from '@/schema'
import packageJson from '../package.json'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
})

describe('v3-only public surface', () => {
  it('does not export legacy client aliases or schema builders', () => {
    expect(v3).not.toHaveProperty('EncryptionV3')
    expect(v3).not.toHaveProperty('typedClient')
    expect(root).not.toHaveProperty('encryptedColumn')
    expect(root).not.toHaveProperty('encryptedField')
    // `encryptedTable` is the one the root entry actually shipped: before
    // `a3830f0d`, `src/index.ts` carried
    // `export { encryptedColumn, encryptedField, encryptedTable } from '@/schema'`
    // and the diff replaced that whole line with a type-only export. All three
    // names must stay off the root — `encryptedTable` is the v2 table builder
    // there, and re-adding it would restore v2 authoring on the default entry
    // under a name that reads identically to the v3 builder callers import from
    // `@cipherstash/stack/v3`. Asserting only the other two would have missed it.
    expect(root).not.toHaveProperty('encryptedTable')
    expect(schema).not.toHaveProperty('encryptedColumn')
    expect(schema).not.toHaveProperty('encryptedTable')
  })

  it('removes the client subpath export', () => {
    expect(packageJson.exports).not.toHaveProperty('./client')
    expect(packageJson.typesVersions['*']).not.toHaveProperty('client')
  })

  /**
   * The stale-map hazard #815 asked to close: a client re-initialised with a
   * different encrypt config would keep the reconstructor map and unknown-table
   * guard derived from the schema tuple captured at construction. A table added
   * by the re-init would then encrypt successfully and fail to decrypt — a
   * silent asymmetry, since both halves report success right up to the point
   * the plaintext comes back wrong-shaped.
   *
   * It is closed structurally: config and reconstructors are derived from the
   * same tuple in the same call, and nothing re-derives either afterwards. This
   * pins that. Re-adding an `init` passthrough — the shape that carried the
   * hazard before `a3830f0d` removed the typed-client surface — fails here.
   *
   * The assertion is exact equality rather than a denylist of suspect names.
   * `createEncryptionClient` returns a plain object literal
   * (`src/encryption/client-v3.ts`), so the member set is fully knowable, and
   * the hazard is "a method that re-derives the schema-dependent state" — not
   * "a method called `init`". A denylist only catches spellings someone thought
   * of in advance; `withSchemas()`, `update()` or `setEncryptConfig()` would all
   * carry the same stale-map hazard and all pass a name-by-name check. Exact
   * equality fails on ANY added member, which forces the decision back through
   * review. Update this list deliberately when the client surface changes.
   */
  it('exposes no re-initialization path that could outlive the schema-derived maps', () => {
    // Annotated so the static type is pinned alongside the runtime member set —
    // a member added to `EncryptionClient<S>` but not to the object literal (or
    // vice versa) is as much a regression as one added to both.
    const client: EncryptionClient<readonly [typeof users]> =
      createEncryptionClient({} as never, users)

    expect(Object.keys(client).sort()).toEqual([
      'bulkDecrypt',
      'bulkDecryptModels',
      'bulkEncrypt',
      'bulkEncryptModels',
      'decrypt',
      'decryptModel',
      'encrypt',
      'encryptModel',
      'encryptQuery',
      'getEncryptConfig',
    ])
  })
})
