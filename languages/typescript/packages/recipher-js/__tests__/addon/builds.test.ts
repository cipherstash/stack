/**
 * The ESM and the CommonJS builds in one process: an application that
 * imports the package and a dependency that requires it. Both load the one
 * addon, so they share its classes, and a ciphertext from either opens in
 * the other. Runs the built `dist/`, in a Node process of its own;
 * `test:addon` builds it first.
 */
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
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
const out = {
  sameClasses: esm.Cipher === cjs.Cipher && esm.Ciphertext === cjs.Ciphertext,
  cipherIsCipher: fromCjs instanceof esm.Cipher && fromEsm instanceof cjs.Cipher,
  ciphertextIsCiphertext: sealed instanceof cjs.Ciphertext,
  esmOpensCjs: (await fromEsm.decrypt(read)).unwrap(),
  cjsOpensEsm: (await fromCjs.decrypt(sealed)).unwrap(),
}
console.log(JSON.stringify(out))
`

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
      sameClasses: true,
      cipherIsCipher: true,
      ciphertextIsCiphertext: true,
      esmOpensCjs: 'shared',
      cjsOpensEsm: 'shared',
    })
  })
})
