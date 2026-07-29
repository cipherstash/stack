import { describe, expect, it } from 'vitest'
import * as v3 from '@/encryption/v3'
import * as root from '@/index'
import * as schema from '@/schema'
import packageJson from '../package.json'

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
})
