import { spawn } from 'node:child_process'
import stripAnsi from 'strip-ansi'
import { STASH_BIN } from './pty.js'

export interface RunOptions {
  cwd?: string
  env?: Record<string, string>
}

export interface RunResult {
  exitCode: number
  signal: NodeJS.Signals | null
  /** ANSI-stripped combined stdout + stderr. */
  output: string
  /** Raw combined stdout + stderr including ANSI escapes. */
  raw: string
  stdout: string
  stderr: string
}

/**
 * Run the built CLI to completion over plain pipes and capture all output.
 *
 * Prefer this over {@link render} for NON-INTERACTIVE commands (`--help`,
 * `--version`, usage/error paths). A pipe buffers the child's output in the
 * Node process and delivers every byte before `close`, so large bursts are
 * never truncated.
 *
 * A PTY, by contrast, loses data on Linux: when the child writes a big burst
 * (the ~5KB `--help` text is a single `console.log`) and exits immediately,
 * the kernel discards whatever is still unread in the pty buffer when the
 * slave closes. On a loaded CI runner node-pty can't drain fast enough, so the
 * tail of the help — the Examples section — goes missing and assertions on it
 * flake. (macOS ptys keep buffered data on close, which is why it only bites
 * in CI.) Post-exit "drain" waits can't help because the bytes are gone before
 * `onData` ever fires. Only interactive tests that must send keystrokes or
 * exercise TTY-specific rendering need {@link render}.
 */
export function run(args: string[], opts: RunOptions = {}): Promise<RunResult> {
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    // Mirror render()'s env so both helpers hit the same CLI code paths.
    NO_COLOR: '1',
    FORCE_COLOR: '0',
    CI: 'true',
    ...(opts.env ?? {}),
  }

  const child = spawn(process.execPath, [STASH_BIN, ...args], {
    cwd: opts.cwd ?? process.cwd(),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  let stdout = ''
  let stderr = ''
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', (d: string) => {
    stdout += d
  })
  child.stderr.on('data', (d: string) => {
    stderr += d
  })

  return new Promise<RunResult>((res, rej) => {
    child.on('error', rej)
    child.on('close', (code, signal) => {
      const raw = stdout + stderr
      res({
        exitCode: code ?? 0,
        signal,
        output: stripAnsi(raw),
        raw,
        stdout: stripAnsi(stdout),
        stderr: stripAnsi(stderr),
      })
    })
  })
}
