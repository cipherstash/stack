import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

const HAS_KEY =
  !!process.env.CS_CLIENT_ACCESS_KEY && !!process.env.CS_WORKSPACE_CRN

// Layer B in `docs/plans/cli-pty-integration-tests.md` (auth follow-up):
// when CI provides `CS_CLIENT_ACCESS_KEY` + `CS_WORKSPACE_CRN`, run `init`
// against real CTS via `AccessKeyStrategy`. Local devs without the secrets
// see this as skipped, never as a flake.
//
// What this *does* exercise: pty → spawned CLI → real `@cipherstash/auth`
// NAPI → real CTS → `authenticateStep` consume-side rendering.
// What it *does not*: the OAuth device-code orchestration in
// `commands/auth/login.ts` — that's covered by the unit suite.
describe.skipIf(!HAS_KEY)('init — real-CTS auth via access key', () => {
  it('detects the access key and logs "Using workspace …"', async () => {
    // Cast through string — the `skipIf` guard above ensures both vars are
    // populated before this body runs, but Biome's noNonNullAssertion
    // doesn't follow the guard.
    const r = render(['init'], {
      env: {
        CS_CLIENT_ACCESS_KEY: String(process.env.CS_CLIENT_ACCESS_KEY),
        CS_WORKSPACE_CRN: String(process.env.CS_WORKSPACE_CRN),
      },
    })

    // The next step after authenticate will prompt or fail — we don't care
    // which, only that we got past auth. Token mint can take a few seconds
    // on a cold CTS instance, so allow a generous window.
    await r.waitFor(messages.auth.usingWorkspace, 20_000)

    r.key('CtrlC')
    await r.exit
    expect(r.output).toContain(messages.auth.usingWorkspace)
  })
})
