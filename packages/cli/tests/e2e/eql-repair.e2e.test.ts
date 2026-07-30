import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { run } from '../helpers/run.js'

/**
 * `stash eql repair --drizzle` end to end: argv parsing, dispatch, the sweep,
 * and the exit code — the wiring the unit tests deliberately do not cover
 * (they call `eqlRepairCommand` directly).
 *
 * The applied-state check is not exercised here: it needs a live Postgres, and
 * its logic has unit coverage against a faked driver. What matters at this
 * level is that the command exists, routes, repairs, and exits correctly.
 */
describe('stash eql repair', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'stash-repair-e2e-'))
  })
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('exits 1 with the target message when --drizzle is missing', async () => {
    const r = await run(['eql', 'repair'], { cwd: tmp })
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain(messages.eql.repairNeedsTarget)
  })

  it('rewrites a broken ALTER COLUMN in the --out directory', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(join(out, 'meta'), { recursive: true })
    writeFileSync(
      join(out, '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    writeFileSync(
      join(out, '0001_encrypt-email.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_text_search";\n',
    )
    writeFileSync(
      join(out, 'meta', '_journal.json'),
      JSON.stringify({
        version: '7',
        dialect: 'postgresql',
        entries: [
          { idx: 0, version: '7', when: 1, tag: '0000_declare' },
          { idx: 1, version: '7', when: 2, tag: '0001_encrypt-email' },
        ],
      }),
    )

    const r = await run(['eql', 'repair', '--drizzle', '--out', out], {
      cwd: tmp,
    })

    expect(r.exitCode).toBe(0)
    // Framed like every other top-level command, so the output reads as one
    // run rather than loose log lines.
    expect(r.output).toContain('CipherStash EQL repair')
    const rewritten = readFileSync(join(out, '0001_encrypt-email.sql'), 'utf-8')
    expect(rewritten).toContain(
      'ADD COLUMN "email_encrypted" "public"."eql_v3_text_search"',
    )
    expect(rewritten).not.toContain('SET DATA TYPE')
  })
})
