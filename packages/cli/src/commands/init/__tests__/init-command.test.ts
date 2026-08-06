import * as p from '@clack/prompts'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CliExit } from '../../../cli/exit.js'
import { messages } from '../../../messages.js'
import type { InitProvider, InitState } from '../types.js'

// `--region` is the non-interactive escape hatch for `stash init`; it must land
// on `state.regionFlag` before the authenticate step runs (that step calls
// `resolveRegion({ regionFlag: state.regionFlag })`). Mock every init step so
// the pipeline is inert and observable — `authenticateStep.run` is the spy we
// assert on; the rest just pass state through. Also keeps native-loading steps
// (`authenticate`, `install-deps`) out of the fast suite.
// Typed with the provider argument the pipeline actually passes, so the
// provider assertions below read it off the call directly instead of asserting
// their way past a one-element tuple type.
const authRun = vi.hoisted(() =>
  vi.fn(async (state: InitState, _provider: InitProvider) => state),
)
const passthrough = { run: async (s: InitState) => s }
// Controllable so the honest-summary tests can vary whether EQL installed.
const eqlRun = vi.hoisted(() =>
  vi.fn(async (s: InitState) => ({ ...s, eqlInstalled: true })),
)

vi.mock('../steps/authenticate.js', () => ({
  authenticateStep: { id: 'authenticate', name: 'Authenticate', run: authRun },
}))
vi.mock('../steps/resolve-database.js', () => ({
  resolveDatabaseStep: { id: 'resolve-database', ...passthrough },
}))
vi.mock('../steps/build-schema.js', () => ({
  buildSchemaStep: { id: 'build-schema', ...passthrough },
}))
vi.mock('../steps/install-deps.js', () => ({
  installDepsStep: { id: 'install-deps', ...passthrough },
}))
vi.mock('../steps/install-eql.js', () => ({
  // A successful init installs EQL — the default mark keeps the honest-summary
  // gate (`eqlPending` → exit 1) happy for the region-threading runs. The
  // honest-summary tests override `eqlRun` per case.
  installEqlStep: { id: 'install-eql', run: eqlRun },
}))
vi.mock('../steps/gather-context.js', () => ({
  gatherContextStep: { id: 'gather-context', ...passthrough },
}))
// `initCommand` may chain into `stash plan`; keep it inert (never reached in the
// non-TTY test env, but mocked so its module graph never loads).
vi.mock('../../plan/index.js', () => ({ planCommand: vi.fn(async () => {}) }))
vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  confirm: vi.fn(),
  isCancel: vi.fn(() => false),
  cancel: vi.fn(),
  log: { info: vi.fn(), success: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

const { initCommand } = await import('../index.js')

beforeEach(() => {
  vi.clearAllMocks()
})

describe('initCommand — region threading', () => {
  it('seeds state.regionFlag from values.region before authenticate runs', async () => {
    await initCommand({}, { region: 'us-east-1' })

    expect(authRun).toHaveBeenCalledTimes(1)
    // The authenticate step (first in the pipeline) must see the region.
    expect(authRun).toHaveBeenCalledWith(
      expect.objectContaining({ regionFlag: 'us-east-1' }),
      expect.anything(),
    )
  })

  it('leaves regionFlag unset when --region is absent', async () => {
    await initCommand({}, {})

    expect(authRun).toHaveBeenCalledTimes(1)
    const [stateArg] = authRun.mock.calls[0]
    expect(stateArg.regionFlag).toBeUndefined()
  })
})

describe('initCommand — integration flags', () => {
  it('selects the Prisma provider (name `prisma`) for `--prisma`', async () => {
    await initCommand({ prisma: true }, {})

    expect(authRun).toHaveBeenCalledTimes(1)
    // Steps receive the resolved provider as their second argument; `--prisma`
    // must resolve to the Prisma Next provider whose referrer name is `prisma`.
    const providerArg = authRun.mock.calls[0][1]
    expect(providerArg.name).toBe('prisma')
  })

  it('keeps the combined name for referrer tracking, and carries both flags on `selected`', async () => {
    // Two contracts in one run. `name` is the referrer: `authenticateStep`
    // passes it straight to `login()`, and `stash auth login --drizzle
    // --supabase` records the same alphabetical 'drizzle-supabase' — a refactor
    // that changes it silently changes attribution. `selected` is what every
    // routing decision reads instead, precisely so nothing has to parse `name`.
    await initCommand({ drizzle: true, supabase: true }, {})

    const providerArg = authRun.mock.calls[0][1]
    expect(providerArg.name).toBe('drizzle-supabase')
    expect(providerArg.selected).toEqual(['supabase', 'drizzle'])
  })

  it('leaves a single-flag run with its plain provider name', async () => {
    // The other side of the combined case: one flag must still produce the
    // bare name (the referrer `stash auth login --supabase` records) and a
    // one-element `selected`.
    await initCommand({ supabase: true }, {})

    const providerArg = authRun.mock.calls[0][1]
    expect(providerArg.name).toBe('supabase')
    expect(providerArg.selected).toEqual(['supabase'])
  })

  it('leaves a flagless run on the base provider with nothing selected', async () => {
    await initCommand({}, {})

    const providerArg = authRun.mock.calls[0][1]
    expect(providerArg.name).toBe('base')
    expect(providerArg.selected).toEqual([])
  })

  it('errors on the renamed `--prisma-next` flag before running any step', async () => {
    // `--prisma-next` was renamed to `--prisma`; init must fail loudly with
    // guidance rather than silently ignore a previously-documented flag.
    await expect(
      initCommand({ 'prisma-next': true }, {}),
    ).rejects.toBeInstanceOf(CliExit)
    expect(authRun).not.toHaveBeenCalled()
  })
})

describe('initCommand — honest summary', () => {
  it('exits non-zero and reports "Setup incomplete" when EQL was not installed', async () => {
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      eqlInstalled: false,
    }))

    await expect(initCommand({}, {})).rejects.toBeInstanceOf(CliExit)
    // The summary titles the run as incomplete, and the EQL fix is surfaced.
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.any(String),
      messages.init.setupIncomplete,
    )
    expect(vi.mocked(p.log.error)).toHaveBeenCalledWith(
      expect.stringContaining(messages.init.eqlNotInstalled),
    )
  })

  it('completes (no throw) when EQL was not installed but the integration is prisma-next', async () => {
    // Prisma Next installs EQL via `prisma-next migrate`, so eqlInstalled=false is
    // expected there and must NOT be treated as an incomplete setup.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'prisma-next',
      eqlInstalled: false,
    }))

    await expect(initCommand({}, {})).resolves.toBeUndefined()
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.any(String),
      'Setup complete',
    )
  })

  it('reports a generated Drizzle migration honestly — not installed, not incomplete', async () => {
    // Differential review (PR #687): the Drizzle flow GENERATES an EQL
    // migration; `installEqlStep` returns eqlMigrationPending (not
    // eqlInstalled). The summary must neither claim "✓ EQL extension
    // installed" nor hard-fail as "Setup incomplete" — it should say a
    // migration was generated and point at `drizzle-kit migrate`, then exit 0.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'drizzle',
      eqlInstalled: false,
      eqlMigrationPending: true,
    }))

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    const summary = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Setup complete')
    expect(summary).toBeDefined()
    const body = summary?.[0] as string
    expect(body).toContain('EQL migration generated')
    expect(body).toContain('drizzle-kit migrate')
    expect(body).not.toContain('✓ EQL extension installed')
  })

  it('points a Supabase migration run at supabase, not drizzle-kit', async () => {
    // Regression: the apply-command branch read `state.integration`, which
    // `detectIntegration` sets from the DATABASE_URL host — and a LOCAL
    // Supabase stack is `127.0.0.1:54322`, so integration lands on
    // 'postgresql' while the provider is 'supabase'. `installEqlStep` routes on
    // either signal, so it generated a Supabase migration and the summary then
    // told the user to run `drizzle-kit migrate`, contradicting the provider's
    // own next-steps block a few lines later. That is exactly the local-dev
    // user this feature targets.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'postgresql',
      eqlInstalled: false,
      eqlMigrationPending: true,
    }))

    await expect(initCommand({ supabase: true }, {})).resolves.toBeUndefined()

    const summary = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Setup complete')
    const body = summary?.[0] as string
    expect(body).toContain('EQL migration generated')
    expect(body).toContain('supabase db reset')
    expect(body).not.toContain('drizzle-kit migrate')
    // This run really did write the file, so the verb must stay "generated".
    expect(body).not.toContain('already present')
  })

  it('says "already present" — not "generated" — when init found the migration on disk', async () => {
    // `installEqlStep` returns `eqlMigrationPending` for BOTH the migration it
    // just wrote and one a previous run (or a standalone `stash eql migration
    // --supabase`) left on disk. The apply guidance is identical either way —
    // the file still has to be applied — but "EQL migration generated" over a
    // run that generated nothing is a claim the user can disprove from their
    // own diff. `eqlMigrationAlreadyPresent` carries the distinction.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      // The local-Supabase shape: `detectIntegration` reads the host from the
      // DATABASE_URL, and `127.0.0.1:54322` lands on 'postgresql' — only the
      // provider says Supabase.
      integration: 'postgresql',
      eqlInstalled: false,
      eqlMigrationPending: true,
      eqlMigrationAlreadyPresent: true,
    }))

    await expect(initCommand({ supabase: true }, {})).resolves.toBeUndefined()

    const summary = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Setup complete')
    expect(summary).toBeDefined()
    const body = summary?.[0] as string
    expect(body).toContain('EQL migration already present')
    expect(body).not.toContain('generated')
    // Unchanged from the freshly-generated case: the same apply guidance, the
    // same successful exit. An already-present migration is not an incomplete
    // setup, so no ✗ line and no non-zero exit.
    expect(body).toContain('supabase db reset')
    expect(body).not.toContain('✗ EQL extension NOT installed')
    expect(vi.mocked(p.note)).not.toHaveBeenCalledWith(
      expect.any(String),
      messages.init.setupIncomplete,
    )
  })

  it('still points a Drizzle-on-Supabase run at drizzle-kit', async () => {
    // The mirror image: `--supabase` is only the grants modifier there, and
    // drizzle-kit owns the migration history, so the apply command is its own.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'drizzle',
      eqlInstalled: false,
      eqlMigrationPending: true,
    }))

    await expect(
      initCommand({ drizzle: true, supabase: true }, {}),
    ).resolves.toBeUndefined()

    const summary = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Setup complete')
    const body = summary?.[0] as string
    expect(body).toContain('drizzle-kit migrate')
    expect(body).not.toContain('supabase db reset')
  })

  it('names drizzle-kit for a combined `--drizzle --supabase` run on a local Supabase stack', async () => {
    // The same host-detection blind spot as the Supabase case above, but with
    // both flags passed: `integration` lands on 'postgresql', so the apply-step
    // routing has only the flags to go on. Reading them off the combined
    // provider name ('drizzle-supabase') matched neither branch, so the run
    // fell through to the drizzle-kit default for the wrong reason — right
    // string, no reasoning behind it, and it would have printed `supabase db
    // reset` the moment the default flipped. Drizzle wins here on purpose: it
    // owns the migration history and `--supabase` is only the grants modifier.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'postgresql',
      eqlInstalled: false,
      eqlMigrationPending: true,
    }))

    await expect(
      initCommand({ drizzle: true, supabase: true }, {}),
    ).resolves.toBeUndefined()

    const summary = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Setup complete')
    const body = summary?.[0] as string
    expect(body).toContain('EQL migration generated')
    expect(body).toContain('drizzle-kit migrate')
    expect(body).not.toContain('supabase db reset')
  })

  it('names drizzle-kit for a combined run whose host says supabase', async () => {
    // A Drizzle project on a HOSTED Supabase database: `detectIntegration`
    // reads the supabase host and sets integration 'supabase', while the user
    // passed both flags. `installEqlStep` writes the migration into the
    // DRIZZLE folder (drizzle owns the history), so the summary has to say
    // `drizzle-kit migrate`. Matching on the combined provider name made
    // `isDrizzle` false, leaving only the integration signal — which says
    // supabase — so the summary told the user to run `supabase db reset` over
    // a migration that was never written into supabase/migrations/.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'supabase',
      eqlInstalled: false,
      eqlMigrationPending: true,
    }))

    await expect(
      initCommand({ drizzle: true, supabase: true }, {}),
    ).resolves.toBeUndefined()

    const summary = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Setup complete')
    const body = summary?.[0] as string
    expect(body).toContain('drizzle-kit migrate')
    expect(body).not.toContain('supabase db reset')
  })

  it('summary says "kept (existing file)" when an existing client is kept', async () => {
    // The three-way encryption-client checkmark fork was untested — the keep
    // path (`build-schema` sets clientFilePath + schemaGenerated: false) now
    // produces a different string with nothing locking it. This fails against
    // the pre-change code, which always claimed "scaffolded".
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      eqlInstalled: true,
      clientFilePath: './src/encryption/index.ts',
      schemaGenerated: false,
    }))

    await initCommand({}, {})
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.stringContaining('✓ Encryption client kept (existing file)'),
      'Setup complete',
    )
  })

  it('summary says "scaffolded" when a placeholder was written', async () => {
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      eqlInstalled: true,
      clientFilePath: './src/encryption/index.ts',
      schemaGenerated: true,
    }))

    await initCommand({}, {})
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.stringContaining('✓ Encryption client scaffolded'),
      'Setup complete',
    )
  })
})

describe('initCommand — CI detection on the `stash plan` chain offer', () => {
  // Regression: this gate was `process.stdout.isTTY`, which consulted CI not
  // at all. A CI runner with an allocated TTY reached the confirm and blocked
  // on /dev/tty forever — a hang, not an error. It also asked about the wrong
  // stream: a redirected stdin still hangs the prompt. Now `isInteractive()`
  // (stdin + isCiEnv, which accepts 1/true in any case).
  const originalStdinIsTTY = process.stdin.isTTY
  const originalStdoutIsTTY = process.stdout.isTTY

  // Force BOTH streams. A CI runner that allocates a TTY has stdin *and*
  // stdout as TTYs — that is the configuration this gate used to hang in, and
  // setting stdin alone would let the old `process.stdout.isTTY` gate pass
  // these tests for the wrong reason (vitest's own stdout is not a TTY).
  beforeEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: true,
      configurable: true,
    })
    Object.defineProperty(process.stdout, 'isTTY', {
      value: true,
      configurable: true,
    })
  })

  afterEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: originalStdinIsTTY,
      configurable: true,
    })
    Object.defineProperty(process.stdout, 'isTTY', {
      value: originalStdoutIsTTY,
      configurable: true,
    })
    vi.unstubAllEnvs()
  })

  for (const ciValue of ['1', 'TRUE', 'true']) {
    it(`skips the chain offer under CI=${ciValue} even with a TTY`, async () => {
      vi.stubEnv('CI', ciValue)

      await expect(initCommand({}, {})).resolves.toBeUndefined()

      // Non-interactive must skip the offer, not fail: init still completes,
      // and steers the user at `plan --target` instead of blocking.
      expect(vi.mocked(p.confirm)).not.toHaveBeenCalled()
      expect(vi.mocked(p.outro)).toHaveBeenCalledWith(
        expect.stringContaining('--target'),
      )
    })
  }

  it('offers the chain when CI is unset and stdin is a TTY', async () => {
    vi.stubEnv('CI', '')
    vi.mocked(p.confirm).mockResolvedValueOnce(false)

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    expect(vi.mocked(p.confirm)).toHaveBeenCalledTimes(1)
  })

  it('skips the chain offer when stdin is redirected even if stdout is a TTY', async () => {
    // The gate keys off stdin, not stdout: `stash init < /dev/null` from a
    // terminal (stdin piped, stdout still a TTY) must not reach the confirm.
    // Reinstating `process.stdout.isTTY` would keep the CI loop above green,
    // so only this stdin/stdout split pins the correct stream.
    vi.stubEnv('CI', '')
    Object.defineProperty(process.stdin, 'isTTY', {
      value: false,
      configurable: true,
    })
    Object.defineProperty(process.stdout, 'isTTY', {
      value: true,
      configurable: true,
    })

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    expect(vi.mocked(p.confirm)).not.toHaveBeenCalled()
    expect(vi.mocked(p.outro)).toHaveBeenCalledWith(
      expect.stringContaining('--target'),
    )
  })

  it('chains into `stash plan` when the offer is accepted', async () => {
    // The accept arm (outro + planCommand() + early return) is what the gate
    // change made reachable; the only other confirm test resolves `false`.
    vi.stubEnv('CI', '')
    vi.mocked(p.confirm).mockResolvedValueOnce(true)
    const { planCommand } = await import('../../plan/index.js')

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    expect(vi.mocked(planCommand)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(p.outro)).toHaveBeenCalledWith(
      expect.stringContaining('handing off to `stash plan`'),
    )
    // The accept path returns early — it must not also print the --target hint.
    expect(vi.mocked(p.outro)).not.toHaveBeenCalledWith(
      expect.stringContaining('--target'),
    )
  })
})
