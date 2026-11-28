/**
 * The loader, against fake native builds: none of these tests needs the
 * addon.
 */
import { describe, expect, it } from 'vitest'
import { BINDING_INTERFACE, type Binding, load } from '../../src/binding'
import { classesOf } from '../../src/cipher'
import { RecipherError } from '../../src/error'
import { checkDeclarationsOf } from '../../src/record'
import { Err, err, Ok } from '../../src/result'

/** A fake native build that exports every name the loader checks. */
function fakeBuild(overrides: Record<string, unknown> = {}) {
  return {
    Cipher: class {},
    Keyset: class {},
    Ciphertext: class {},
    Json: class {},
    bindingInterface: () => BINDING_INTERFACE,
    checkDeclarations: () => undefined,
    createTesting: () => Promise.resolve('cipher'),
    installResult: () => true,
    json: () => ({}),
    RcDate: class {},
    RcTimestamp: class {},
    RcDecimal: class {},
    RcUuid: class {},
    ...overrides,
  }
}

const requiring = (exported: unknown) => () => exported

describe('load', () => {
  it('loads a build that implements this binding interface', () => {
    expect(load(requiring(fakeBuild()), '/x/recipher.node').isOk()).toBe(true)
  })

  it('is an Err, not a throw, when the build does not load', () => {
    const loaded = load(() => {
      throw new Error('ENOENT: no such file')
    }, '/x/recipher.node')
    expect(loaded.err()?.code).toBe('recipher_js::load')
    expect(loaded.err()?.message).toContain('build:debug')
    expect(loaded.err()?.message).not.toContain('ENOENT')
  })

  it('is an Err when the build lacks an export', () => {
    for (const name of [
      'Cipher',
      'Keyset',
      'Ciphertext',
      'Json',
      'bindingInterface',
      'checkDeclarations',
      'createTesting',
      'installResult',
      'json',
      'RcDate',
      'RcTimestamp',
      'RcDecimal',
      'RcUuid',
    ]) {
      const loaded = load(
        requiring(fakeBuild({ [name]: undefined })),
        '/x/recipher.node',
      )
      expect(loaded.err()?.code, name).toBe('recipher_js::load')
    }
    expect(load(requiring(null), '/x').err()?.code).toBe('recipher_js::load')
  })

  it('is an Err when the build implements another interface', () => {
    const loaded = load(
      requiring(fakeBuild({ bindingInterface: () => BINDING_INTERFACE + 1 })),
      '/x/recipher.node',
    )
    expect(loaded.err()?.code).toBe('recipher_js::binding_interface')
    const throwing = load(
      requiring(
        fakeBuild({
          bindingInterface: () => {
            throw new Error('x')
          },
        }),
      ),
      '/x/recipher.node',
    )
    expect(throwing.err()?.code).toBe('recipher_js::binding_interface')
  })
})

describe('installResult', () => {
  it('gives the build the classes of a Result when it loads', () => {
    const given: unknown[] = []
    const loaded = load(
      requiring(
        fakeBuild({ installResult: (classes: unknown) => given.push(classes) }),
      ),
      '/x/recipher.node',
    )
    expect(loaded.isOk()).toBe(true)
    expect(given).toEqual([{ Ok, Err, RecipherError }])
  })

  it('is an Err, not a throw, when the build refuses them', () => {
    const loaded = load(
      requiring(
        fakeBuild({
          installResult: () => {
            throw new TypeError('no')
          },
        }),
      ),
      '/x/recipher.node',
    )
    expect(loaded.err()?.code).toBe('recipher_js::load')
  })

  it('freezes the classes of a build that loaded', () => {
    const build = fakeBuild()
    load(requiring(build), '/x/recipher.node')
    for (const cls of [
      build.Cipher,
      build.Keyset,
      build.Ciphertext,
      build.Json,
    ]) {
      expect(Object.isFrozen(cls)).toBe(true)
      expect(Object.isFrozen(cls.prototype)).toBe(true)
    }
  })
})

describe('the classes of a build that did not load', () => {
  const error = new RecipherError({
    code: 'recipher_js::load',
    message: 'did not load',
  })
  const classes = classesOf(err<RecipherError, Binding>(error))

  it('resolve every call to the load error', async () => {
    expect((await classes.Cipher.create()).err()).toBe(error)
    expect(classes.Ciphertext.fromBytes(new Uint8Array(4)).err()).toBe(error)
    expect((await classes.createTesting(new Uint8Array(32))).err()).toBe(error)
    expect(checkDeclarationsOf(err(error))([]).err()).toBe(error)
  })

  it('recognise no value as one of theirs', () => {
    expect({} instanceof classes.Cipher).toBe(false)
    expect({} instanceof classes.Ciphertext).toBe(false)
    expect({} instanceof classes.Keyset).toBe(false)
  })
})
