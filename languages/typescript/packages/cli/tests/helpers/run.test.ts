import { describe, expect, it } from 'vitest'
import { buildRunResult } from './run.js'

// Unit coverage for the pure `close`-event → RunResult mapping extracted
// from `run()`. `run()` itself always spawns the built CLI binary and
// exposes no handle to signal the child, which makes the signal-terminated
// path (the headline fix in aedfd9d) impractical to exercise deterministically
// through an E2E test. Testing the extracted pure function directly avoids
// needing a timeout/SIGKILL escape hatch or other API surface change.
describe('buildRunResult', () => {
  it('reports a clean exit', () => {
    const r = buildRunResult(0, null, 'hello\n', '')
    expect(r.exitCode).toBe(0)
    expect(r.signal).toBeNull()
    expect(r.stdout).toBe('hello\n')
    expect(r.output).toBe('hello\n')
  })

  it('reports a non-zero exit code', () => {
    const r = buildRunResult(1, null, '', 'boom\n')
    expect(r.exitCode).toBe(1)
    expect(r.signal).toBeNull()
    expect(r.stderr).toBe('boom\n')
  })

  it('keeps exitCode null (never masked to 0) when the child is signal-terminated', () => {
    // Node guarantees exactly one of code/signal is non-null on 'close'. A
    // naive `code ?? 0` would collapse this to a "successful" exit 0, hiding
    // a crash/OOM/SIGTERM kill from callers.
    const r = buildRunResult(null, 'SIGTERM', '', '')
    expect(r.exitCode).toBeNull()
    expect(r.signal).toBe('SIGTERM')
  })

  it('strips ANSI codes independently from stdout/stderr while combining into output/raw', () => {
    // Build the ESC control byte at runtime (rather than embedding it
    // literally in the source) to keep this file free of non-printable
    // characters.
    const ESC = String.fromCharCode(27)
    const green = `${ESC}[32mok${ESC}[0m`
    const red = `${ESC}[31merr${ESC}[0m`
    const r = buildRunResult(0, null, green, red)
    expect(r.stdout).toBe('ok')
    expect(r.stderr).toBe('err')
    expect(r.output).toBe('okerr')
    expect(r.raw).toBe(green + red)
  })
})
