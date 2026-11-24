/**
 * The ESM and the CommonJS builds in one process: an application that
 * imports the package and a dependency that requires it. Both load the one
 * addon, so they share its classes, and a ciphertext from either opens in
 * the other. And the package with no native build at all. Each runs the
 * built `dist/`, in a Node process of its own; `test:addon` builds it
 * first.
 */
import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const dist = (file: string) =>
  fileURLToPath(new URL(`../../dist/${file}`, import.meta.url))

const SCRIPT = `
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
const [esmIndex, esmTesting, cjsIndex, cjsTesting] = process.argv.slice(1)
const require = createRequire(import.meta.url)
const esm = await import(pathToFileURL(esmIndex).href)
const cjs = require(cjsIndex)
const fromEsm = (await (await import(pathToFileURL(esmTesting).href)).testCipher()).unwrap()
const fromCjs = (await require(cjsTesting).testCipher()).unwrap()
const sealed = (await fromEsm.defaultKeyset().encrypt('shared')).unwrap()
const read = cjs.Ciphertext.fromBytes(sealed.toBytes()).unwrap()
const people = cjs.record('people', { email: cjs.encrypt(cjs.kinds.string, { index: ['equality'] }) })
const row = (await fromEsm.defaultKeyset().encrypt(people, { email: 'a@example.com' })).unwrap()
const out = {
  recordAcrossBuilds: (await fromEsm.decrypt(people, row)).unwrap().email,
  sameClasses: esm.Cipher === cjs.Cipher && esm.Ciphertext === cjs.Ciphertext,
  cipherIsCipher: fromCjs instanceof esm.Cipher && fromEsm instanceof cjs.Cipher,
  ciphertextIsCiphertext: sealed instanceof cjs.Ciphertext,
  esmOpensCjs: (await fromEsm.decrypt(read)).unwrap(),
  cjsOpensEsm: (await fromCjs.decrypt(sealed)).unwrap(),
}
console.log(JSON.stringify(out))
`

const MISSING = `
const recipher = await import(process.argv[1])
const testing = await import(process.argv[2])
const out = {}
out.date = new recipher.VcDate('2026-11-23').value
out.dateFrozen = Object.isFrozen(new recipher.VcDate('2026-11-23'))
out.json = String(recipher.json({ a: 1 }))
out.create = (await recipher.Cipher.create()).err().code
out.testing = (await testing.testCipher()).err().code
out.fromBytes = recipher.Ciphertext.fromBytes(new Uint8Array(4)).err().code
out.notACipher = {} instanceof recipher.Cipher
console.log(JSON.stringify(out))
`

describe('the package without its native build', () => {
  it('imports, constructs the wrapper classes, and resolves every call to the load error', () => {
    const dir = mkdtempSync(join(tmpdir(), 'recipher-missing-'))
    try {
      cpSync(
        fileURLToPath(new URL('../../dist', import.meta.url)),
        join(dir, 'dist'),
        {
          recursive: true,
        },
      )
      writeFileSync(join(dir, 'package.json'), '{"type":"module"}')
      const output = execFileSync(
        process.execPath,
        [
          '--input-type=module',
          '--eval',
          MISSING,
          '--',
          join(dir, 'dist', 'index.js'),
          join(dir, 'dist', 'testing.js'),
        ],
        { encoding: 'utf8' },
      )
      expect(JSON.parse(output)).toEqual({
        date: '2026-11-23',
        dateFrozen: true,
        json: 'Json(***)',
        create: 'recipher::load',
        testing: 'recipher::load',
        fromBytes: 'recipher::load',
        notACipher: false,
      })
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('the ESM and CommonJS builds in one process', () => {
  it('share the native classes, so each opens what the other sealed', () => {
    const files = ['index.js', 'testing.js', 'index.cjs', 'testing.cjs'].map(
      dist,
    )
    for (const file of files) {
      expect(existsSync(file), `${file}: run \`build\` first`).toBe(true)
    }
    const output = execFileSync(
      process.execPath,
      ['--input-type=module', '--eval', SCRIPT, '--', ...files],
      { encoding: 'utf8' },
    )
    expect(JSON.parse(output)).toEqual({
      recordAcrossBuilds: 'a@example.com',
      sameClasses: true,
      cipherIsCipher: true,
      ciphertextIsCiphertext: true,
      esmOpensCjs: 'shared',
      cjsOpensEsm: 'shared',
    })
  })
})
