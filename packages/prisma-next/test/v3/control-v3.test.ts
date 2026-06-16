import { describe, expect, it } from 'vitest'
import cipherstashExtensionDescriptor from '../../src/exports/control'
import {
  CIPHERSTASH_STRING_V3_CODEC_ID,
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
} from '../../src/extension-metadata/constants'
import { cipherstashStringV3CodecHooks } from '../../src/migration/codec-hooks-v3'

describe('cipherstash control descriptor (v3)', () => {
  it('registers cipherstashStringV3CodecHooks keyed by the v3 codec id', () => {
    const hooks = (
      cipherstashExtensionDescriptor as unknown as {
        types: { codecTypes: { controlPlaneHooks: Record<string, unknown> } }
      }
    ).types.codecTypes.controlPlaneHooks
    expect(hooks[CIPHERSTASH_STRING_V3_CODEC_ID]).toBe(cipherstashStringV3CodecHooks)
  })

  it('includes the v3 baseline migration in the contract space', () => {
    const cs = (
      cipherstashExtensionDescriptor as unknown as {
        contractSpace: { migrations: ReadonlyArray<{ dirName: string }> }
      }
    ).contractSpace
    expect(cs.migrations.map((m) => m.dirName)).toContain(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME)
  })
})
