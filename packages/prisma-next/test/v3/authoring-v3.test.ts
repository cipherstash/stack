import { describe, expect, it } from 'vitest'
import { cipherstashAuthoringTypes } from '../../src/contract-authoring'
import { CIPHERSTASH_STRING_V3_CODEC_ID } from '../../src/extension-metadata/constants'

describe('cipherstash.EncryptedStringV3 PSL constructor', () => {
  const ctor = cipherstashAuthoringTypes.cipherstash.EncryptedStringV3

  it('is a namespaced type constructor', () => {
    expect(ctor.kind).toBe('typeConstructor')
  })

  it('declares a single required object arg with a required string `index` property', () => {
    expect(ctor).toMatchObject({
      args: [
        {
          kind: 'object',
          name: 'options',
          optional: false,
          properties: { index: { kind: 'string', optional: false } },
        },
      ],
    })
  })

  it('lowers to the v3 codec id + base storage domain, threading index through typeParams', () => {
    expect(ctor.output).toMatchObject({
      codecId: CIPHERSTASH_STRING_V3_CODEC_ID,
      nativeType: 'eql_v3.text',
      typeParams: { index: { kind: 'arg', index: 0, path: ['index'] } },
    })
  })
})
