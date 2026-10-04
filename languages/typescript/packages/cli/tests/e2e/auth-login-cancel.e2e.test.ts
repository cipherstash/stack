import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

describe('stash auth login — interactive cancel', () => {
  it('shows the region prompt, cancels on ctrl-c, and exits 0', async () => {
    // The pty harness defaults `CI=true` so most tests hit the CLI's
    // non-interactive code paths. This test is the exception — it exercises
    // the interactive region picker, which (like the DATABASE_URL resolver)
    // only renders when we're a real TTY *and* not in CI. Override CI back to
    // empty so `resolveRegion` takes the interactive branch.
    const r = render(['auth', 'login'], { env: { CI: '' } })

    // First clack prompt — `selectRegion()` runs synchronously before any
    // network activity, so this is a deterministic assertion target.
    await r.waitFor(messages.auth.selectRegion)

    r.key('CtrlC')

    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    expect(r.output).toContain(messages.auth.cancelled)
  })
})
