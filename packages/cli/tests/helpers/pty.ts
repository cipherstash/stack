import { chmodSync, existsSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { type IPty, spawn } from 'node-pty'
import stripAnsi from 'strip-ansi'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Built CLI binary. Tests assume `pnpm --filter stash build` has run.
export const STASH_BIN = resolve(__dirname, '../../dist/bin/stash.js')

// pnpm strips the executable bit when unpacking node-pty's macOS prebuilds,
// causing `posix_spawnp` to fail with EACCES. Re-add it on first import.
// Linux builds from source and doesn't ship a spawn-helper, so the file is
// absent there — guard with existsSync.
function ensureSpawnHelperExecutable() {
  try {
    const require = createRequire(import.meta.url)
    const pkg = require.resolve('node-pty/package.json')
    const helper = join(dirname(pkg), 'build/Release/spawn-helper')
    const prebuilt = join(
      dirname(pkg),
      `prebuilds/${process.platform}-${process.arch}/spawn-helper`,
    )
    for (const path of [helper, prebuilt]) {
      if (!existsSync(path)) continue
      const mode = statSync(path).mode
      // Owner-execute bit (0o100). Skip the chmod call when already set.
      if ((mode & 0o100) === 0) chmodSync(path, mode | 0o755)
    }
  } catch {
    // Best-effort: if we can't fix it here, the spawn() call will surface
    // a clear posix_spawnp error and the user can chmod manually.
  }
}

ensureSpawnHelperExecutable()

export type Key =
  | 'Enter'
  | 'Up'
  | 'Down'
  | 'Left'
  | 'Right'
  | 'Space'
  | 'Tab'
  | 'Backspace'
  | 'CtrlC'
  | 'CtrlD'
  | 'Esc'

const KEYS: Record<Key, string> = {
  Enter: '\r',
  Up: '\x1b[A',
  Down: '\x1b[B',
  Left: '\x1b[D',
  Right: '\x1b[C',
  Space: ' ',
  Tab: '\t',
  Backspace: '\x7f',
  CtrlC: '\x03',
  CtrlD: '\x04',
  Esc: '\x1b',
}

export interface RenderOptions {
  cwd?: string
  env?: Record<string, string>
  cols?: number
  rows?: number
}

export interface Rendered {
  pty: IPty
  /** ANSI-stripped cumulative stdout. */
  readonly output: string
  /** Raw cumulative stdout including ANSI escapes. */
  readonly raw: string
  /** Resolves with the process exit code when the pty exits. */
  exit: Promise<{ exitCode: number; signal?: number }>
  write(data: string): void
  key(k: Key): void
  /**
   * Polls until `match` appears in the ANSI-stripped output. Rejects on
   * timeout. Useful for waiting on a clack prompt to render before sending
   * input.
   */
  waitFor(match: string | RegExp, timeoutMs?: number): Promise<void>
  kill(signal?: string): void
}

export function render(args: string[], opts: RenderOptions = {}): Rendered {
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    // Force-disable color codes from the CLI itself; we still strip ANSI on
    // assertions, but suppressing where possible keeps `raw` readable when
    // debugging a failure.
    NO_COLOR: '1',
    FORCE_COLOR: '0',
    // Match the convention the CLI itself uses (e.g. install.ts checks
    // `process.env.CI !== 'true'`) so test runs hit the same code paths.
    CI: 'true',
    ...(opts.env ?? {}),
  }

  // Use the absolute path to the current node binary — node-pty's
  // `posix_spawnp` doesn't inherit PATH lookup reliably across all macOS /
  // Linux configurations, especially under Vitest's fork pool.
  const pty = spawn(process.execPath, [STASH_BIN, ...args], {
    cwd: opts.cwd ?? process.cwd(),
    cols: opts.cols ?? 100,
    rows: opts.rows ?? 30,
    env,
  })

  let raw = ''
  pty.onData((d) => {
    raw += d
  })

  const exit = new Promise<{ exitCode: number; signal?: number }>((res) => {
    pty.onExit((e) => res(e))
  })

  const waitFor = async (match: string | RegExp, timeoutMs = 5_000) => {
    const deadline = Date.now() + timeoutMs
    const matches = (s: string) => {
      if (typeof match === 'string') return s.includes(match)
      // Reset stateful regex (`/g`/`/y`) state so successive .test() calls
      // don't drift through the buffer.
      match.lastIndex = 0
      return match.test(s)
    }
    if (matches(stripAnsi(raw))) return
    await new Promise<void>((res, rej) => {
      const timer = setTimeout(
        () => {
          cleanup()
          rej(
            new Error(
              `Timed out after ${timeoutMs}ms waiting for ${
                typeof match === 'string' ? JSON.stringify(match) : match
              }. Output so far:\n${stripAnsi(raw)}`,
            ),
          )
        },
        Math.max(0, deadline - Date.now()),
      )
      const sub = pty.onData(() => {
        if (matches(stripAnsi(raw))) {
          cleanup()
          res()
        }
      })
      const cleanup = () => {
        clearTimeout(timer)
        sub.dispose()
      }
    })
  }

  return {
    pty,
    get output() {
      return stripAnsi(raw)
    },
    get raw() {
      return raw
    },
    exit,
    write: (data: string) => pty.write(data),
    key: (k: Key) => pty.write(KEYS[k]),
    waitFor,
    kill: (signal?: string) => pty.kill(signal),
  }
}
