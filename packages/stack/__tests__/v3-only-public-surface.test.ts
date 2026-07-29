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
   */
  it('exposes no re-initialization path that could outlive the schema-derived maps', () => {
    const client = createEncryptionClient({} as never, users)

    for (const method of ['init', 'reinit', 'initialize', 'configure']) {
      expect(client).not.toHaveProperty(method)
    }
  })
})
