import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CALLER_ENV_VARS, resolveCaller } from '../tty.js'

describe('resolveCaller', () => {
  // This repo's own agent harness sets some caller markers ambiently, so clear
  // every consulted var before each case; otherwise the fallback tests would
  // pick up e.g. CLAUDECODE from the process running the suite.
  beforeEach(() => {
    for (const name of CALLER_ENV_VARS) vi.stubEnv(name, '')
  })
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  /** Force process.stdin.isTTY for the fallback cases; restored after each test. */
  function withStdinTty(isTTY: boolean, run: () => void): void {
    const original = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY')
    Object.defineProperty(process.stdin, 'isTTY', {
      value: isTTY,
      configurable: true,
    })
    try {
      run()
    } finally {
      if (original) Object.defineProperty(process.stdin, 'isTTY', original)
      else delete (process.stdin as { isTTY?: boolean }).isTTY
    }
  }

  it('detects Claude Code via CLAUDECODE', () => {
    vi.stubEnv('CLAUDECODE', '1')
    expect(resolveCaller()).toBe('claude-code')
  })

  it('detects Claude Code via the CLAUDE_CODE_ENTRYPOINT backup marker', () => {
    vi.stubEnv('CLAUDE_CODE_ENTRYPOINT', 'cli')
    expect(resolveCaller()).toBe('claude-code')
  })

  it('detects Cursor via CURSOR_TRACE_ID', () => {
    vi.stubEnv('CURSOR_TRACE_ID', 'abc-123')
    expect(resolveCaller()).toBe('cursor')
  })

  it('detects Codex via CODEX_SANDBOX', () => {
    vi.stubEnv('CODEX_SANDBOX', 'seatbelt')
    expect(resolveCaller()).toBe('codex')
  })

  it('confirmed agents outrank the editor marker (Cursor also sets TERM_PROGRAM=vscode)', () => {
    vi.stubEnv('CURSOR_TRACE_ID', 'abc-123')
    vi.stubEnv('TERM_PROGRAM', 'vscode')
    expect(resolveCaller()).toBe('cursor')
  })

  it('the first agent marker wins when several are present', () => {
    vi.stubEnv('CLAUDECODE', '1')
    vi.stubEnv('CURSOR_TRACE_ID', 'abc-123')
    expect(resolveCaller()).toBe('claude-code')
  })

  it('classifies a VS Code-family editor terminal as editor, not an agent', () => {
    vi.stubEnv('TERM_PROGRAM', 'vscode')
    expect(resolveCaller()).toBe('editor')
  })

  it('is case-insensitive on TERM_PROGRAM', () => {
    vi.stubEnv('TERM_PROGRAM', 'vsCode')
    expect(resolveCaller()).toBe('editor')
  })

  it('ignores whitespace-only marker values', () => {
    vi.stubEnv('CLAUDECODE', '   ')
    withStdinTty(true, () => expect(resolveCaller()).toBe('interactive'))
  })

  it('falls back to interactive when stdin is a TTY and no marker is set', () => {
    withStdinTty(true, () => expect(resolveCaller()).toBe('interactive'))
  })

  it('falls back to non-interactive when stdin is not a TTY', () => {
    withStdinTty(false, () => expect(resolveCaller()).toBe('non-interactive'))
  })
})
