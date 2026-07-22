import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { messages } from '../../../messages.js'
import { prismaNextInstallGuard } from '../install.js'

describe('prismaNextInstallGuard', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'pn-install-guard-'))
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('blocks with actionable guidance when a prisma-next.config is present', () => {
    writeFileSync(join(dir, 'prisma-next.config.ts'), 'export default {}')

    const msg = prismaNextInstallGuard(dir, {})
    expect(msg).not.toBeNull()
    expect(msg).toContain(messages.eql.prismaNextDetected)
    expect(msg).toContain('prisma-next migrate')
    expect(msg).toContain('--force')
  })

  it('blocks when @cipherstash/prisma-next is a dependency', () => {
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ dependencies: { '@cipherstash/prisma-next': '1.0.0' } }),
    )

    expect(prismaNextInstallGuard(dir, {})).toContain(
      messages.eql.prismaNextDetected,
    )
  })

  it('returns null (allows) with --force, even in a prisma-next project', () => {
    writeFileSync(join(dir, 'prisma-next.config.ts'), 'export default {}')

    expect(prismaNextInstallGuard(dir, { force: true })).toBeNull()
  })

  it('returns null (allows) when the project is not Prisma Next', () => {
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { '@cipherstash/stack-drizzle': '1.0.0' },
      }),
    )

    expect(prismaNextInstallGuard(dir, {})).toBeNull()
  })
})
