import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CliExit } from '../../../cli/exit.js'
import { implCommand } from '../index.js'
import { howToProceedStep } from '../steps/how-to-proceed.js'

// `implCommand` reaches the plan-summary checkpoint via `p.confirm`, which
// reads /dev/tty. Stub just that export (the rest of @clack/prompts stays
// real) so the CI-detection cases can assert whether the prompt was reached.
const confirmMock = vi.hoisted(() => vi.fn())
vi.mock('@clack/prompts', async () => {
  const actual =
    await vi.importActual<typeof import('@clack/prompts')>('@clack/prompts')
  return { ...actual, confirm: confirmMock }
})

let originalIsTTY: boolean | undefined
let originalCwd: string
let tmpDir: string

function writeContext() {
  fs.mkdirSync(path.join(tmpDir, '.cipherstash'), { recursive: true })
  fs.writeFileSync(
    path.join(tmpDir, '.cipherstash', 'context.json'),
    JSON.stringify({
      integration: 'postgresql',
      packageManager: 'npm',
      schemas: [],
    }),
  )
}

function writePlan() {
  fs.writeFileSync(path.join(tmpDir, '.cipherstash', 'plan.md'), '# Plan')
}

// `implCommand` gates interactivity on `process.stdin.isTTY` (a redirected
// stdin still hangs the agent-target picker), so the tests mock stdin.
function setIsTTY(value: boolean) {
  Object.defineProperty(process.stdin, 'isTTY', {
    value,
    configurable: true,
  })
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-impl-test-'))
  originalCwd = process.cwd()
  originalIsTTY = process.stdin.isTTY
  process.chdir(tmpDir)
  writeContext()
  writePlan()
})

afterEach(() => {
  process.chdir(originalCwd)
  Object.defineProperty(process.stdin, 'isTTY', {
    value: originalIsTTY,
    configurable: true,
  })
  vi.restoreAllMocks()
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  }
})

describe('implCommand — TTY handling', () => {
  it('exits cleanly without running the agent-target picker when stdin is not a TTY and no --target is given', async () => {
    setIsTTY(false)
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)

    await expect(implCommand({}, {})).resolves.toBeUndefined()

    // The whole point of the fix: when there's no TTY and no target, the
    // command must NOT reach the picker (which reads from /dev/tty and
    // would hang forever in automation).
    expect(runSpy).not.toHaveBeenCalled()
  })

  it('runs the handoff with the pre-resolved target when --target is given in a non-TTY context', async () => {
    setIsTTY(false)
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)

    await implCommand({}, { target: 'agents-md' })

    expect(runSpy).toHaveBeenCalledTimes(1)
    const state = runSpy.mock.calls[0][0]
    expect(state.handoff).toBe('agents-md')
  })

  it('exits with status 1 when --target is an unknown value', async () => {
    setIsTTY(false)
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)

    await expect(implCommand({}, { target: 'bogus' })).rejects.toThrow(
      'process.exit',
    )
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(runSpy).not.toHaveBeenCalled()
  })
})

describe('implCommand — CI detection with a TTY attached', () => {
  // Regression: the gate used to be an inline `process.env.CI !== 'true'`,
  // which only recognised the exact lowercase spelling. A CI runner that sets
  // CI=1 or CI=TRUE *and* allocates a TTY made `stash impl` believe it was
  // interactive, so it blocked on the plan-summary confirm (or the
  // agent-target picker) forever — a hang, not an error. The gate now goes
  // through `isInteractive()` in config/tty.ts, whose `isCiEnv()` accepts
  // 1/true in any case.
  beforeEach(() => {
    setIsTTY(true)
    confirmMock.mockReset()
    confirmMock.mockResolvedValue(true)
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  for (const ciValue of ['1', 'TRUE', 'true']) {
    it(`treats CI=${ciValue} as non-interactive even with a TTY`, async () => {
      vi.stubEnv('CI', ciValue)
      const runSpy = vi
        .spyOn(howToProceedStep, 'run')
        .mockResolvedValue({} as never)

      await expect(implCommand({}, {})).resolves.toBeUndefined()

      // Neither blocking prompt may be reached.
      expect(confirmMock).not.toHaveBeenCalled()
      expect(runSpy).not.toHaveBeenCalled()
    })
  }

  it('does not re-confirm --continue-without-plan under CI when no plan exists', async () => {
    // The flag is the consent. Prompting again under CI blocks on /dev/tty,
    // and the confirm is default-no, so a resolved prompt would cancel a run
    // the user explicitly asked for.
    vi.stubEnv('CI', '1')
    fs.rmSync(path.join(tmpDir, '.cipherstash', 'plan.md'))
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)

    await expect(
      implCommand({ 'continue-without-plan': true }, {}),
    ).resolves.toBeUndefined()

    expect(confirmMock).not.toHaveBeenCalled()
    expect(runSpy).not.toHaveBeenCalled()
  })

  it('is interactive when CI is unset and stdin is a TTY', async () => {
    vi.stubEnv('CI', '')
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)

    await implCommand({}, {})

    expect(confirmMock).toHaveBeenCalledTimes(1)
    expect(runSpy).toHaveBeenCalledTimes(1)
  })

  it('performs the handoff under CI=1 when --target is given', async () => {
    // Non-interactive means "don't prompt", not "don't run". A regression
    // that made the command bail early under CI would keep the not-called
    // cases above green — this locks the automation happy path.
    vi.stubEnv('CI', '1')
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)

    await implCommand({}, { target: 'agents-md' })

    expect(confirmMock).not.toHaveBeenCalled()
    expect(runSpy).toHaveBeenCalledTimes(1)
    expect(runSpy.mock.calls[0][0].handoff).toBe('agents-md')
  })

  it('runs the selected handoff under CI with --continue-without-plan and no plan', async () => {
    // The specific path the `if (isTTY)` gate at index.ts opened up: flag +
    // target, no plan on disk — it must run the handoff without re-confirming.
    vi.stubEnv('CI', '1')
    fs.rmSync(path.join(tmpDir, '.cipherstash', 'plan.md'))
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)

    await implCommand(
      { 'continue-without-plan': true },
      { target: 'agents-md' },
    )

    expect(confirmMock).not.toHaveBeenCalled()
    expect(runSpy).toHaveBeenCalledTimes(1)
    expect(runSpy.mock.calls[0][0].handoff).toBe('agents-md')
  })

  it('exits 1 with the plan hint under CI=1 when no plan and no --continue-without-plan', async () => {
    // CI=1 flips isTTY to false, rerouting a no-plan / no-flag run out of the
    // interactive `select` and into the `else if (!isTTY)` error + exit(1). It
    // must fail loudly, not render the "No plan found" select and block.
    vi.stubEnv('CI', '1')
    fs.rmSync(path.join(tmpDir, '.cipherstash', 'plan.md'))
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)

    await expect(implCommand({}, {})).rejects.toThrow('process.exit')

    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(confirmMock).not.toHaveBeenCalled()
  })

  it('still confirms --continue-without-plan interactively, and declining aborts', async () => {
    // The honour-the-prompt half of the `if (isTTY)` gate: with a TTY and CI
    // unset the default-no confirm must still fire, and declining it must abort
    // (CancelledError → CliExit) rather than fall through to the handoff.
    vi.stubEnv('CI', '')
    fs.rmSync(path.join(tmpDir, '.cipherstash', 'plan.md'))
    confirmMock.mockReset()
    confirmMock.mockResolvedValue(false)
    const runSpy = vi
      .spyOn(howToProceedStep, 'run')
      .mockResolvedValue({} as never)

    await expect(
      implCommand({ 'continue-without-plan': true }, {}),
    ).rejects.toBeInstanceOf(CliExit)

    expect(confirmMock).toHaveBeenCalledTimes(1)
    expect(runSpy).not.toHaveBeenCalled()
  })
})
