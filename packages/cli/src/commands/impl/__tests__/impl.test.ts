import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { implCommand } from '../index.js'
import { howToProceedStep } from '../steps/how-to-proceed.js'

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
