import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * `stash eql install` must refuse in a Prisma Next project (Prisma Next owns
 * EQL installation via its own migration ledger). The guard fires before any
 * database I/O, so this needs no DB — and proves the wiring end-to-end (the
 * pure guard is unit-tested separately).
 */
describe('stash eql install — Prisma Next guard', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'eql-install-pn-e2e-'))
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('refuses with actionable guidance and exits 1 (no DB needed)', async () => {
    writeFileSync(join(dir, 'prisma-next.config.ts'), 'export default {}')

    const r = await runPiped(['eql', 'install'], { cwd: dir, timeoutMs: 15000 })

    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.eql.prismaNextDetected)
    expect(out).toContain('prisma-next migration apply')
    expect(out).toContain('--force')
  })
})
