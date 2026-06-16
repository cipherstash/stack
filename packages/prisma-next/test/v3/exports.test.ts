import { describe, expect, it } from 'vitest'
import { createCipherstashRuntimeDescriptor } from '../../src/exports/runtime'
import { makeFakeSdk } from './helpers/fake-sdk'

describe('v3 runtime descriptor', () => {
  it('advertises the v3 string codec and the v3-capable operators', () => {
    const desc = createCipherstashRuntimeDescriptor({ sdk: makeFakeSdk() })
    expect(desc.codecs?.().map((c: { codecId: string }) => c.codecId)).toContain('cipherstash/string-v3@1')
    // cipherstashEq attaches to the v3 codec via the shared cipherstash:string trait.
    expect(Object.keys(desc.queryOperations?.() ?? {})).toContain('cipherstashEq')
  })
})

describe('v3 public re-exports', () => {
  it('exposes the v3 surface from @cipherstash/prisma-next/runtime', async () => {
    const runtime = await import('../../src/exports/runtime')
    expect(typeof runtime.createCipherstashStringV3Codec).toBe('function')
    expect(typeof runtime.queryTypeForIndex).toBe('function')
    expect(runtime.CIPHERSTASH_STRING_V3_CODEC_ID).toBe('cipherstash/string-v3@1')
    expect(typeof runtime.encryptedStringV3ParamsSchema).toBe('function')
    expect(typeof runtime.renderEncryptedStringV3OutputType).toBe('function')
  })

  it('exposes encryptedStringV3 from @cipherstash/prisma-next/column-types', async () => {
    const columnTypes = await import('../../src/exports/column-types')
    expect(typeof columnTypes.encryptedStringV3).toBe('function')
  })

  it('exposes bulkEncryptV3Middleware from @cipherstash/prisma-next/middleware', async () => {
    const mw = await import('../../src/exports/middleware')
    expect(typeof mw.bulkEncryptV3Middleware).toBe('function')
  })
})
