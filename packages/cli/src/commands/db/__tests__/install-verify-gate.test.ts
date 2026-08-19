/**
 * `verifySurfaceOrExit` — the #890 gate `installCommand` runs on both the
 * fresh-install tail and the already-installed early exit. The differ's own
 * behaviour is covered in `installer/__tests__/verify.test.ts`; what lives
 * here is the install-side POLICY layered on top of the report:
 *
 * - damage exits 1 (a committed-but-incomplete install must not read as
 *   success);
 * - a version mismatch does NOT — `ok: false` there means "nothing was
 *   checked", and a no-op `eql install` re-run over an older EQL was exit 0
 *   before verification existed. Idempotent provisioning scripts (and
 *   `stash init`, whose direct-install route calls `installCommand` inside a
 *   try/catch that `process.exit` escapes) depend on that. `stash eql verify`
 *   keeps the strict gate; the installer must not inherit it.
 * - a verification error (connection dropped) warns and continues — the
 *   install itself is committed.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { VerifyReport } from '@/installer/verify.js'
import { verifySurfaceOrExit } from '../install.js'

const clack = vi.hoisted(() => ({
  spinnerInstance: { start: vi.fn(), stop: vi.fn() },
  log: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    success: vi.fn(),
    step: vi.fn(),
  },
  intro: vi.fn(),
  note: vi.fn(),
  outro: vi.fn(),
}))
vi.mock('@clack/prompts', () => ({
  spinner: vi.fn(() => clack.spinnerInstance),
  log: clack.log,
  intro: clack.intro,
  note: clack.note,
  outro: clack.outro,
}))

const verifier = vi.hoisted(() => ({ verifyEqlSurface: vi.fn() }))
vi.mock('@/installer/verify.js', () => ({
  verifyEqlSurface: verifier.verifyEqlSurface,
}))

// Imported dynamically by the damage path for its findings renderer.
const findingsReporter = vi.hoisted(() => ({ reportVerifyFindings: vi.fn() }))
vi.mock('../../eql/verify.js', () => ({
  reportVerifyFindings: findingsReporter.reportVerifyFindings,
}))

function report(overrides: Partial<VerifyReport>): VerifyReport {
  return {
    status: 'complete',
    bundleVersion: '3.0.4',
    installedVersion: '3.0.4',
    counts: null,
    ore: null,
    findings: [],
    ok: true,
    ...overrides,
  }
}

function spinner() {
  return clack.spinnerInstance as unknown as ReturnType<
    typeof import('@clack/prompts').spinner
  >
}

describe('verifySurfaceOrExit', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns without exiting on a complete surface', async () => {
    verifier.verifyEqlSurface.mockResolvedValueOnce(report({}))
    await expect(
      verifySurfaceOrExit('postgres://db', spinner(), { remedy: 'r' }),
    ).resolves.toBeUndefined()
  })

  it('exits 1 on damage, after reporting the findings and the remedy', async () => {
    verifier.verifyEqlSurface.mockResolvedValueOnce(
      report({
        status: 'incomplete',
        ok: false,
        findings: [
          { severity: 'damage', kind: 'operator', message: 'op missing' },
        ],
      }),
    )
    const exit = vi
      .spyOn(process, 'exit')
      .mockImplementation((code?: string | number | null | undefined) => {
        throw new Error(`exit ${code}`)
      })
    try {
      await expect(
        verifySurfaceOrExit('postgres://db', spinner(), {
          remedy: 'use --force',
        }),
      ).rejects.toThrow('exit 1')
      expect(findingsReporter.reportVerifyFindings).toHaveBeenCalled()
      expect(clack.log.error).toHaveBeenCalledWith('use --force')
    } finally {
      exit.mockRestore()
    }
  })

  it('does NOT exit on a version mismatch — warns with the skew instead', async () => {
    const mismatch = report({
      status: 'version-mismatch',
      installedVersion: '3.0.2',
      ok: false,
      findings: [
        {
          severity: 'warning',
          kind: 'version',
          message:
            'EQL 3.0.2 installed, CLI pins 3.0.4 — run stash eql upgrade',
        },
      ],
    })
    verifier.verifyEqlSurface.mockResolvedValueOnce(mismatch)
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit called')
    })
    try {
      await expect(
        verifySurfaceOrExit('postgres://db', spinner(), { remedy: 'r' }),
      ).resolves.toBeUndefined()
      expect(clack.log.warn).toHaveBeenCalledWith(mismatch.findings[0].message)
      expect(clack.log.error).not.toHaveBeenCalled()
      expect(exit).not.toHaveBeenCalled()
    } finally {
      exit.mockRestore()
    }
  })

  it('warns and continues when verification itself errors', async () => {
    verifier.verifyEqlSurface.mockRejectedValueOnce(
      new Error('connection terminated'),
    )
    await expect(
      verifySurfaceOrExit('postgres://db', spinner(), { remedy: 'r' }),
    ).resolves.toBeUndefined()
    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('connection terminated'),
    )
  })
})
