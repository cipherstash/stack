/**
 * The loader and the adapter, against fake native builds: none of these
 * tests needs the addon.
 */
import { describe, expect, it } from 'vitest'
import {
  adapt,
  BINDING_INTERFACE,
  type Binding,
  load,
  settle,
  settleAsync,
} from '../../src/binding'
import { classesOf } from '../../src/cipher'
import { RecipherError } from '../../src/error'
import { err } from '../../src/result'

/** A fake native build that exports every name the loader checks. */
function fakeBuild(overrides: Record<string, unknown> = {}) {
  return {
    Cipher: class {},
    Keyset: class {},
    Ciphertext: class {},
    bindingInterface: () => BINDING_INTERFACE,
    createTesting: () => Promise.resolve({ ok: true, value: 'cipher' }),
    ...overrides,
  }
}

const requiring = (exported: unknown) => () => exported

describe('load', () => {
  it('loads a build that implements this binding interface', () => {
    expect(load(requiring(fakeBuild()), '/x/recipher.node').isOk()).toBe(true)
  })

  it('is an internal Err, not a throw, when the build does not load', () => {
    const loaded = load(() => {
      throw new Error('ENOENT: no such file')
    }, '/x/recipher.node')
    expect(loaded.err()?.kind).toBe('internal')
    expect(loaded.err()?.code).toBe('recipher::load')
    expect(loaded.err()?.message).toContain('build:debug')
    expect(loaded.err()?.message).not.toContain('ENOENT')
  })

  it('is an internal Err when the build lacks an export', () => {
    for (const name of [
      'Cipher',
      'Keyset',
      'Ciphertext',
      'bindingInterface',
      'createTesting',
    ]) {
      const loaded = load(
        requiring(fakeBuild({ [name]: undefined })),
        '/x/recipher.node',
      )
      expect(loaded.err()?.code, name).toBe('recipher::load')
    }
    expect(load(requiring(null), '/x').err()?.code).toBe('recipher::load')
  })

  it('is an internal Err when the build implements another interface', () => {
    const loaded = load(
      requiring(fakeBuild({ bindingInterface: () => BINDING_INTERFACE + 1 })),
      '/x/recipher.node',
    )
    expect(loaded.err()?.kind).toBe('internal')
    expect(loaded.err()?.code).toBe('recipher::binding_interface')
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
    expect(throwing.err()?.code).toBe('recipher::binding_interface')
  })
})

describe('settle', () => {
  it('reads an outcome as a Result', () => {
    expect(settle(() => ({ ok: true, value: 5 })).unwrap()).toBe(5)
    const failed = settle(() => ({
      ok: false,
      error: { kind: 'value', code: 'recipher::x', message: 'no' },
    }))
    expect(failed.err()).toBeInstanceOf(RecipherError)
    expect(failed.err()?.code).toBe('recipher::x')
  })

  it('turns a throw or a rejection into an internal Err, keeping no text', async () => {
    const thrown = settle(() => {
      throw new TypeError('card 4111 1111 1111 1111')
    })
    expect(thrown.err()?.code).toBe('recipher::threw')
    expect(thrown.err()?.message).not.toContain('4111')

    const rejected = await settleAsync(() =>
      Promise.reject(new Error('card 4111')),
    )
    expect(rejected.err()?.code).toBe('recipher::threw')
    expect(rejected.err()?.message).not.toContain('4111')
  })

  it('refuses something that is not an outcome', () => {
    expect(settle(() => 7 as never).err()?.code).toBe('recipher::outcome')
  })
})

describe('adapt', () => {
  class Native {
    readonly name: string
    constructor(name: string) {
      this.name = name
    }
    greet(other: unknown) {
      if (!(this instanceof Native)) {
        throw new TypeError('not a Native')
      }
      return Promise.resolve({ ok: true, value: `${this.name}:${other}` })
    }
    plain() {
      return this.name
    }
    static make(name: unknown) {
      return { ok: true, value: new Native(String(name)) }
    }
  }
  adapt(Native.prototype, { greet: 'async', plain: 'plain' })
  adapt(Native, { make: 'sync' })
  const adapted = Native as unknown as {
    make(name: string): { unwrap(): Adapted }
    prototype: Adapted
  }
  interface Adapted {
    greet(other: unknown): Promise<{ unwrap(): string; isErr(): boolean }>
    plain(): string
  }

  it('makes a method a Result, bound to its instance when passed alone', async () => {
    const one = adapted.make('one').unwrap()
    expect((await one.greet('x')).unwrap()).toBe('one:x')
    const detached = one.greet
    expect((await detached('y')).unwrap()).toBe('one:y')
    const all = await Promise.all(['a', 'b'].map(one.greet))
    expect(all.map((result) => result.unwrap())).toEqual(['one:a', 'one:b'])
    const { plain } = one
    expect(plain()).toBe('one')
    const { make } = adapted
    expect(make('two').unwrap().plain()).toBe('two')
  })

  it('turns a call on something that is not the class into an Err', async () => {
    const greet = adapted.prototype.greet
    const result = await greet.call({}, 'x')
    expect(result.isErr()).toBe(true)
  })

  it('adapts a class once, and freezes it', () => {
    const before = Object.getOwnPropertyDescriptor(Native.prototype, 'greet')
    adapt(Native.prototype, { greet: 'sync' })
    expect(Object.getOwnPropertyDescriptor(Native.prototype, 'greet')).toEqual(
      before,
    )
    expect(Object.isFrozen(Native.prototype)).toBe(true)
  })
})

describe('the classes of a build that did not load', () => {
  const error = new RecipherError({
    kind: 'internal',
    code: 'recipher::load',
    message: 'did not load',
  })
  const classes = classesOf(err<RecipherError, Binding>(error))

  it('resolve every call to the load error', async () => {
    expect((await classes.Cipher.create()).err()).toBe(error)
    expect(classes.Ciphertext.fromBytes(new Uint8Array(4)).err()).toBe(error)
    expect((await classes.createTesting(new Uint8Array(32))).err()).toBe(error)
  })

  it('recognise no value as one of theirs', () => {
    expect({} instanceof classes.Cipher).toBe(false)
    expect({} instanceof classes.Ciphertext).toBe(false)
    expect({} instanceof classes.Keyset).toBe(false)
  })
})
