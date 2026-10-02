// Verifies that a Node script using protect-ffi exits naturally after
// its work is done — i.e. nothing in this addon pins libuv past the
// completion of awaited operations.
//
// Before this fix:
//   * #[neon::main] installed a process-wide referenced Channel into
//     a static OnceCell, pinning the event loop forever.
//   * `NeonJsAuthStrategy` then held its own referenced Channel for the
//     life of the Client.
//
// After this fix:
//   * The static is gone; the strategy captures a per-call Channel.
//   * That Channel is unref'd inside `from_root` (after the getToken
//     lookup) so the Client doesn't block process exit while idle.
//
// We assert that two scripts — one using `opts.strategy` (JsBacked) and
// one using the env-backed AutoStrategy fallback — terminate on their
// own within a short timeout. If a Channel were still pinning libuv
// the child would hang and the test would fail via timeout.

import 'dotenv/config'
import { type ChildProcess, spawn } from 'node:child_process'
import { resolve } from 'node:path'
import { describe, expect, test } from 'vitest'

const COMMON_ENV = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ACCESS_KEY',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
]
const missingCommonEnv = COMMON_ENV.filter((k) => !process.env[k])

// Generous: we expect the child to exit within ~1s of completing the
// round trip; 15s gives the auth + ZeroKMS round trip plenty of slack
// on slow CI without masking a real hang.
const EXIT_TIMEOUT_MS = 15_000

type ChildOutcome = {
  code: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
  timedOut: boolean
}

function runChild(scriptPath: string): Promise<ChildOutcome> {
  return new Promise((resolveOutcome) => {
    const child: ChildProcess = spawn(process.execPath, [scriptPath], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString()
    })

    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, EXIT_TIMEOUT_MS)

    child.on('exit', (code, signal) => {
      clearTimeout(timer)
      resolveOutcome({ code, signal, stdout, stderr, timedOut })
    })
  })
}

describe.skipIf(missingCommonEnv.length > 0)('event loop exit', () => {
  test(
    'exits naturally after a JsBacked-strategy round trip',
    async () => {
      const script = resolve(__dirname, 'fixtures/event-loop-exit-jsbacked.cjs')
      const outcome = await runChild(script)
      expect(
        outcome.timedOut,
        `child hung; libuv still pinned\nstdout: ${outcome.stdout}\nstderr: ${outcome.stderr}`,
      ).toBe(false)
      expect(
        outcome.code,
        `child failed\nstdout: ${outcome.stdout}\nstderr: ${outcome.stderr}`,
      ).toBe(0)
      expect(outcome.stdout.trim()).toBe('ok')
    },
    EXIT_TIMEOUT_MS + 5_000,
  )

  test(
    'exits naturally with the AutoStrategy fallback',
    async () => {
      const script = resolve(__dirname, 'fixtures/event-loop-exit-auto.cjs')
      const outcome = await runChild(script)
      expect(
        outcome.timedOut,
        `child hung; libuv still pinned\nstdout: ${outcome.stdout}\nstderr: ${outcome.stderr}`,
      ).toBe(false)
      expect(
        outcome.code,
        `child failed\nstdout: ${outcome.stdout}\nstderr: ${outcome.stderr}`,
      ).toBe(0)
      expect(outcome.stdout.trim()).toBe('ok')
    },
    EXIT_TIMEOUT_MS + 5_000,
  )
})
