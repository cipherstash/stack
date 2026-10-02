import { describe, expect, it } from 'vitest'
import * as migrate from '../index.js'

describe('EQL v2 lifecycle retirement', () => {
  it('does not export Proxy configuration or cutover primitives', () => {
    for (const name of [
      'activateConfig',
      'countEncryptedWithActiveConfig',
      'discardPendingConfig',
      'migrateConfig',
      'readyForEncryption',
      'reloadConfig',
      'renameEncryptedColumns',
      'selectPendingColumns',
    ]) {
      expect(migrate).not.toHaveProperty(name)
    }
  })
})
