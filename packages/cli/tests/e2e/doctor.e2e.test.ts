import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

// `doctor` is dispatched by the thin launcher (src/bin/stash.ts) *before* the
// command graph loads, so these also exercise the launcher's top-level path
// and exit codes — the behavior the bin coding guideline asks us to cover.
describe('stash doctor — E2E', () => {
  it('runs the diagnostics and exits 0 on a healthy install', async () => {
    const r = render(['doctor'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    expect(r.output).toContain(messages.doctor.title)
    // Platform line is always emitted regardless of which probes are present.
    expect(r.output).toContain(
      `${messages.doctor.platformLabel} ${process.platform}-${process.arch}`,
    )
    expect(r.output).toContain(messages.doctor.allChecksPassed)
  })

  it('is dispatched even though it is not registered in the help command list', async () => {
    // Guards the launcher path: `doctor` must not fall through to the unknown-
    // command handler (which would exit 1 and print the usage banner).
    const r = render(['doctor'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    expect(r.output).not.toContain(messages.cli.unknownCommand)
  })
})
