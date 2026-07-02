import { spawn } from 'node:child_process'
import stripAnsi from 'strip-ansi'
import { STASH_BIN } from './pty.js'

export interface RunOptions {
  cwd?: string
  env?: Record<string, string>
}

export interface RunResult {
  /**
   * The process's numeric exit code, or `null` when it was terminated by a
   * signal (see {@link RunResult.signal}). Never coerced to 0, so a
   * signal-killed child (crash, SIGKILL) is distinguishable from a clean exit.
   */
  exitCode: number | null
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
  // Preserve the true interleaving order of the combined transcript by
  // recording chunks as they arrive, while keeping stdout/stderr separate.
  const chunks: string[] = []
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', (d: string) => {
    stdout += d
    chunks.push(d)
  })
  child.stderr.on('data', (d: string) => {
    stderr += d
    chunks.push(d)
  })

  return new Promise<RunResult>((res, rej) => {
    child.on('error', rej)
    child.on('close', (code, signal) => {
      res(buildRunResult(code, signal, stdout, stderr, chunks.join('')))
    })
  })
}

/**
 * Pure `close`-event → {@link RunResult} mapping, factored out of `run()` so
 * the exit-code/signal handling can be unit-tested directly without spawning
 * a real child process (see `run.test.ts`). Node guarantees exactly one of
 * `code`/`signal` is non-null on `'close'` — this must never coerce a null
 * `code` to `0`, or a signal-terminated child (crash, SIGKILL, OOM) would be
 * misreported as a clean exit.
 *
 * `raw` defaults to `stdout + stderr` (fine for the unit tests below, which
 * pass pre-baked strings with no real interleaving to preserve); `run()`
 * itself always passes the chunk-interleaved transcript explicitly, since
 * naive concatenation can reorder output relative to a real child process's
 * actual stdout/stderr write sequence.
 */
export function buildRunResult(
  code: number | null,
  signal: NodeJS.Signals | null,
  stdout: string,
  stderr: string,
  raw: string = stdout + stderr,
): RunResult {
  return {
    exitCode: code,
    signal,
    output: stripAnsi(raw),
    raw,
    stdout: stripAnsi(stdout),
    stderr: stripAnsi(stderr),
  }
}
