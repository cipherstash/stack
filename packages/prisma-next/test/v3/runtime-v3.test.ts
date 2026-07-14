/**
 * `createCipherstashV3RuntimeDescriptor({ sdk })` — the consumer-facing
 * v3 wrapper. The v3 twin of `../runtime-descriptor.test.ts`, pinning:
 *
 *   - v3's OWN extension identity (decision 1b) — never the v2 space id;
 *   - the full 40-domain codec surface (including the
 *     authoring-unexposed `*_ord_ore` variants — the codec layer must
 *     decode whatever the catalog can name);
 *   - the `cipherstash:*`-namespaced traits (no framework `equality`);
 *   - the registered v3 query-operation method set.
 */

import { describe, expect, it, vi } from 'vitest'
import type { CipherstashSdk } from '../../src/execution/sdk'
import {
  CIPHERSTASH_SPACE_ID,
  CIPHERSTASH_STRING_CODEC_ID,
} from '../../src/extension-metadata/constants'
import {
  CIPHERSTASH_V3_CODEC_IDS,
  CIPHERSTASH_V3_EXTENSION_VERSION,
  CIPHERSTASH_V3_SPACE_ID,
} from '../../src/extension-metadata/constants-v3'
import { cipherstashV3QueryOperations } from '../../src/v3/operators-v3'
import { createCipherstashV3RuntimeDescriptor } from '../../src/v3/runtime-v3'

function emptySdk(): CipherstashSdk {
  return {
    decrypt: vi.fn(),
    bulkEncrypt: vi.fn(),
    bulkDecrypt: vi.fn(),
  }
}

describe('createCipherstashV3RuntimeDescriptor — descriptor shape', () => {
  it('declares kind=extension under the v3 id/version (never the v2 id)', () => {
    const descriptor = createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })
    expect(descriptor.kind).toBe('extension')
    expect(descriptor.id).toBe(CIPHERSTASH_V3_SPACE_ID)
    expect(descriptor.id).not.toBe(CIPHERSTASH_SPACE_ID)
    expect(descriptor.version).toBe(CIPHERSTASH_V3_EXTENSION_VERSION)
    expect(descriptor.familyId).toBe('sql')
    expect(descriptor.targetId).toBe('postgres')
  })

  it('exposes one codec descriptor per catalog domain (all 40) on both surfaces', () => {
    const descriptor = createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })
    const viaTypes = descriptor.types?.codecTypes?.codecDescriptors ?? []
    const viaCodecs = descriptor.codecs?.() ?? []
    expect(viaTypes.map((c) => c.codecId).sort()).toEqual(
      [...CIPHERSTASH_V3_CODEC_IDS].sort(),
    )
    expect(viaCodecs.map((c) => c.codecId).sort()).toEqual(
      [...CIPHERSTASH_V3_CODEC_IDS].sort(),
    )
    // Never a v2 codec id.
    expect(viaCodecs.map((c) => c.codecId)).not.toContain(
      CIPHERSTASH_STRING_CODEC_ID,
    )
  })

  it('every queryable codec carries only cipherstash:* namespaced traits', () => {
    const descriptor = createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })
    for (const codec of descriptor.codecs?.() ?? []) {
      const traits: ReadonlyArray<string> = codec.traits ?? []
      expect(traits.includes('equality')).toBe(false)
      for (const trait of traits) {
        expect(trait.startsWith('cipherstash:')).toBe(true)
      }
    }
  })

  it('registers the full v3 query-operation method set', () => {
    const descriptor = createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })
    const methods = Object.keys(descriptor.queryOperations?.() ?? {})
    expect(methods.sort()).toEqual(
      Object.keys(cipherstashV3QueryOperations()).sort(),
    )
    expect(methods).toContain('cipherstashEq')
    expect(methods).toContain('cipherstashJsonContains')
  })

  it('create() returns a target-bound SQL/Postgres instance', () => {
    const descriptor = createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })
    const instance = descriptor.create()
    expect(instance.familyId).toBe('sql')
    expect(instance.targetId).toBe('postgres')
  })
})

describe('createCipherstashV3RuntimeDescriptor — SDK isolation per descriptor', () => {
  it('produces a different codec instance per invocation so per-tenant SDKs do not cross-talk', () => {
    const a = createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })
    const b = createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })
    const params = { castAs: 'string', capabilities: {} }
    const codecA = a.codecs?.()[0]?.factory(params)({ name: 'x.y' })
    const codecB = b.codecs?.()[0]?.factory(params)({ name: 'x.y' })
    expect(codecA).toBeDefined()
    expect(codecA).not.toBe(codecB)
  })
})
