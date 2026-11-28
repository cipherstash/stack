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
// The addon builds every Result from the classes of the build that loaded
// first. instanceof must still hold for the other build's classes.
const fromCjs_ = cjs.Ciphertext.fromBytes(new Uint8Array(1))
const fromEsm_ = esm.Ciphertext.fromBytes(new Uint8Array(1))
const okCjs = cjs.Ciphertext.fromBytes(sealed.toBytes())
const out = {
  sameClasses: esm.Cipher === cjs.Cipher && esm.Ciphertext === cjs.Ciphertext,
  cipherIsCipher: fromCjs instanceof esm.Cipher && fromEsm instanceof cjs.Cipher,
  ciphertextIsCiphertext: sealed instanceof cjs.Ciphertext,
  esmOpensCjs: (await fromEsm.decrypt(read)).unwrap(),
  cjsOpensEsm: (await fromCjs.decrypt(sealed)).unwrap(),
  errIsErr: [fromCjs_, fromEsm_].every(
    (r) => r instanceof esm.Err && r instanceof cjs.Err && !(r instanceof cjs.Ok),
  ),
  okIsOk: okCjs instanceof esm.Ok && okCjs instanceof cjs.Ok && !(okCjs instanceof esm.Err),
  errorIsRecipherError: [fromCjs_, fromEsm_].every(
    (r) => r.error instanceof esm.RecipherError && r.error instanceof cjs.RecipherError,
  ),
  ownOkIsOk: cjs.ok(1) instanceof esm.Ok && esm.err(1) instanceof cjs.Err,
  plainIsNotOk: !({ value: 1 } instanceof esm.Ok) && !(null instanceof cjs.Err),
}
console.log(JSON.stringify(out))
`

const MISSING = `
const recipher = await import(process.argv[1])
const testing = await import(process.argv[2])
const out = {}
out.date = new recipher.RcDate('2026-11-23').value
out.dateFrozen = Object.isFrozen(new recipher.RcDate('2026-11-23'))
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
        create: 'recipher_js::load',
        testing: 'recipher_js::load',
        fromBytes: 'recipher_js::load',
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
      sameClasses: true,
      cipherIsCipher: true,
      ciphertextIsCiphertext: true,
      esmOpensCjs: 'shared',
      cjsOpensEsm: 'shared',
      errIsErr: true,
      okIsOk: true,
      errorIsRecipherError: true,
      ownOkIsOk: true,
      plainIsNotOk: true,
    })
  })
})

// A worker thread loads the addon in a JavaScript environment of its own,
// which needs its own Result classes. The main thread loads the package
// first, so a worker that used the main thread's classes, or none, would
// fail here.
const WORKER = `
import { pathToFileURL } from 'node:url'
import { Worker } from 'node:worker_threads'
const [esmTesting, cjsTesting, cjsIndex] = process.argv.slice(1)
const main = (await (await import(pathToFileURL(esmTesting).href)).testCipher()).unwrap()
const sealed = (await main.defaultKeyset().encrypt('from the main thread')).unwrap()
const worker = new Worker(
  \`
  const { parentPort, workerData } = require('node:worker_threads')
  const { testCipher } = require(workerData.cjsTesting)
  const { Ciphertext, Ok, RecipherError } = require(workerData.cjsIndex)
  ;(async () => {
    const cipher = (await testCipher()).unwrap()
    const sealed = (await cipher.defaultKeyset().encrypt('in a worker')).unwrap()
    const opened = await cipher.decrypt(sealed)
    const fromMain = await cipher.decrypt(Ciphertext.fromBytes(workerData.bytes).unwrap())
    const refused = Ciphertext.fromBytes(new Uint8Array(1))
    parentPort.postMessage({
      opened: opened.unwrap(),
      openedIsOk: opened instanceof Ok,
      fromMain: fromMain.unwrap(),
      refusedIsRecipherError: refused.error instanceof RecipherError,
    })
  })().catch((error) => parentPort.postMessage({ threw: String(error) }))
  \`,
  {
    eval: true,
    // Not the parent's \`--input-type=module\`: the worker is CommonJS.
    execArgv: [],
    workerData: {
      cjsTesting,
      cjsIndex,
      bytes: sealed.toBytes(),
    },
  },
)
const message = await new Promise((resolve, reject) => {
  worker.once('message', resolve)
  worker.once('error', reject)
})
await worker.terminate()
console.log(JSON.stringify(message))
`

describe('a worker thread', () => {
  it('has Result classes of its own, and encrypts and decrypts', () => {
    const files = ['testing.js', 'testing.cjs', 'index.cjs'].map(dist)
    for (const file of files) {
      expect(existsSync(file), `${file}: run \`build\` first`).toBe(true)
    }
    const output = execFileSync(
      process.execPath,
      ['--input-type=module', '--eval', WORKER, '--', ...files],
      { encoding: 'utf8' },
    )
    expect(JSON.parse(output)).toEqual({
      opened: 'in a worker',
      openedIsOk: true,
      fromMain: 'from the main thread',
      refusedIsRecipherError: true,
    })
  })
})
