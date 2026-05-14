import { spawn } from 'node:child_process'
import { STASH_BIN } from './pty.js'

/**
 * Non-PTY counterpart to `render()` in `./pty.ts`. Spawns the built CLI
 * with all three stdio channels as pipes — so the child sees
 * `process.stdout.isTTY === false` and `/dev/tty` is unavailable. This is
 * the exact "non-TTY context" the BUGS.md reproducer described:
 * `bunx stash impl < /dev/null` from CI, automation harnesses, or the
 * Claude Code Bash tool.
 *
 * Use this — not `render()` — when the behaviour under test depends on
 * non-TTY stdio. `render()` (node-pty) always gives the child a real
 * terminal.
 */
export interface PipedResult {
  /** `null` only when the process was SIGKILLed by the timeout. */
  exitCode: number | null
  stdout: string
  stderr: string
  /** True when the timeout fired and we had to kill the process. */
  timedOut: boolean
}

export interface PipedOptions {
  cwd?: string
  env?: Record<string, string>
  /** Default 10s — short enough that a regression of the hang surfaces fast. */
  timeoutMs?: number
}

export function runPiped(
  args: string[],
  opts: PipedOptions = {},
): Promise<PipedResult> {
  return new Promise((resolvePromise, reject) => {
    const env: Record<string, string> = {
      ...(process.env as Record<string, string>),
      NO_COLOR: '1',
      FORCE_COLOR: '0',
      ...(opts.env ?? {}),
    }

    const child = spawn(process.execPath, [STASH_BIN, ...args], {
      cwd: opts.cwd ?? process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    })

    let stdout = ''
    let stderr = ''
    let timedOut = false

    child.stdout?.on('data', (d: Buffer) => {
      stdout += d.toString()
    })
    child.stderr?.on('data', (d: Buffer) => {
      stderr += d.toString()
    })

    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, opts.timeoutMs ?? 10_000)

    child.on('close', (code) => {
      clearTimeout(timer)
      resolvePromise({ exitCode: code, stdout, stderr, timedOut })
    })
    child.on('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
  })
}
