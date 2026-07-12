import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { createBaseProvider } from '../../packages/cli/src/commands/init/providers/base.js'
import { createDrizzleProvider } from '../../packages/cli/src/commands/init/providers/drizzle.js'
import { createSupabaseProvider } from '../../packages/cli/src/commands/init/providers/supabase.js'
import type { PackageManager } from '../../packages/cli/src/commands/init/utils.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(__dirname, '../..')
const WIZARD_BIN = resolve(REPO_ROOT, 'packages/wizard/dist/bin/wizard.js')

const PMS: PackageManager[] = ['npm', 'bun', 'pnpm', 'yarn']
const RUNNER: Record<PackageManager, string> = {
  npm: 'npx',
  bun: 'bunx',
  pnpm: 'pnpm dlx',
  yarn: 'yarn dlx',
}

const BIN = {
  cli: resolve(REPO_ROOT, 'packages/cli/dist/bin/stash.js'),
  wizard: resolve(REPO_ROOT, 'packages/wizard/dist/bin/wizard.js'),
  protect: resolve(REPO_ROOT, 'packages/protect/dist/bin/stash.js'),
  drizzleGen: resolve(
    REPO_ROOT,
    'packages/drizzle/dist/bin/generate-eql-migration.js',
  ),
} as const

const UA: Record<PackageManager, string> = {
  npm: 'npm/10.0.0',
  bun: 'bun/1.0.0',
  pnpm: 'pnpm/10.0.0',
  yarn: 'yarn/4.0.0',
}

// Suite A — pure-function rendering of "Next Steps" via the CLI's init
// providers. Imports source so we exercise the production code path
// without needing the binary to be built.
describe('CLI init providers — package-manager-aware Next Steps', () => {
  const cases: Array<{
    label: string
    create: () => ReturnType<typeof createBaseProvider>
    firstStep: (runner: string) => string
  }> = [
    {
      label: 'base',
      create: createBaseProvider,
      firstStep: (r) => `Set up your database: ${r} stash eql install`,
    },
    {
      label: 'drizzle',
      create: createDrizzleProvider,
      firstStep: (r) =>
        `Set up your database: ${r} stash eql install --drizzle`,
    },
    {
      label: 'supabase',
      create: createSupabaseProvider,
      firstStep: (r) =>
        `Install EQL: ${r} stash eql install --supabase (prompts for migration vs direct)`,
    },
  ]

  for (const { label, create, firstStep } of cases) {
    for (const pm of PMS) {
      it(`${label} provider renders ${RUNNER[pm]} for pm=${pm}`, () => {
        const steps = create().getNextSteps({}, pm)
        expect(steps[0]).toBe(firstStep(RUNNER[pm]))
        // The wizard hint should also use the right runner. The wrapper
        // subcommand is `stash wizard`, so the rendered runner-aware string
        // looks like e.g. `bunx stash wizard`.
        expect(steps.find((s) => s.includes('stash wizard'))).toContain(
          `${RUNNER[pm]} stash wizard`,
        )
        // No accidental npx leakage when the runner isn't npx.
        if (RUNNER[pm] !== 'npx') {
          for (const s of steps) expect(s).not.toMatch(/\bnpx\b/)
        }
      })
    }
  }
})

// Suite B — runs the BUILT wizard binary in throwaway sandbox dirs and
// asserts the runner-aware "Run: ..." line in the prerequisites output.
//
// Requires the user to be authenticated (the wizard's auth check runs
// before the prereq check). Skipped when no auth is configured locally
// and no auth env vars are present in the runner environment. The CI
// job exposes auth secrets explicitly to keep this assertion live.
const authConfigured = (() => {
  if (process.env.CS_CLIENT_ID && process.env.CS_CLIENT_KEY) return true
  const home = process.env.HOME
  if (!home) return false
  return existsSync(join(home, '.cipherstash', 'auth.json'))
})()

describe.skipIf(!authConfigured)(
  'wizard binary — package-manager-aware prerequisites',
  () => {
    let sandbox: string

    beforeAll(() => {
      // The binary must be built — wizard's build is fast (~16ms tsup esbuild).
      // Caller is expected to run it; surface a clear error if absent.
      if (!existsSync(WIZARD_BIN)) {
        throw new Error(
          `Wizard binary not found at ${WIZARD_BIN}. Run \`pnpm --filter @cipherstash/wizard build\` first (turbo's test:e2e task does this automatically).`,
        )
      }
    })

    beforeEach(() => {
      sandbox = mkdtempSync(join(tmpdir(), 'stash-pm-e2e-'))
    })

    afterEach(() => {
      rmSync(sandbox, { recursive: true, force: true })
    })

    function runWizard(opts: {
      lockfile?: string
      userAgent?: string
    }): string {
      if (opts.lockfile) writeFileSync(join(sandbox, opts.lockfile), '')
      try {
        return execFileSync(process.execPath, [WIZARD_BIN], {
          cwd: sandbox,
          env: {
            ...process.env,
            npm_config_user_agent: opts.userAgent ?? '',
          },
          encoding: 'utf-8',
          stdio: ['ignore', 'pipe', 'pipe'],
        })
      } catch (err) {
        // Wizard exits non-zero when prereqs are missing — that's the path
        // we're testing. Surface the captured stdout/stderr from the error.
        const e = err as NodeJS.ErrnoException & {
          stdout?: Buffer | string
          stderr?: Buffer | string
        }
        return [e.stdout?.toString() ?? '', e.stderr?.toString() ?? ''].join(
          '\n',
        )
      }
    }

    describe('lockfile-driven detection', () => {
      it.each([
        { pm: 'bun' as const, lockfile: 'bun.lock' },
        { pm: 'pnpm' as const, lockfile: 'pnpm-lock.yaml' },
        { pm: 'yarn' as const, lockfile: 'yarn.lock' },
      ])('uses $pm runner when $lockfile is present', ({ pm, lockfile }) => {
        const out = runWizard({ lockfile })
        expect(out).toContain(`Run: ${RUNNER[pm]} stash eql install`)
      })

      it('falls back to npx when no lockfile and no user agent', () => {
        const out = runWizard({})
        expect(out).toContain('Run: npx stash eql install')
      })
    })

    describe('user-agent driven detection', () => {
      it.each([
        { pm: 'bun' as const, userAgent: 'bun/1.1.40 npm/? node/v22.3.0' },
        { pm: 'pnpm' as const, userAgent: 'pnpm/9.0.0 npm/? node/v20.0.0' },
        { pm: 'yarn' as const, userAgent: 'yarn/4.0.0 npm/? node/v20.0.0' },
      ])('uses $pm runner when UA is $userAgent', ({ pm, userAgent }) => {
        const out = runWizard({ userAgent })
        expect(out).toContain(`Run: ${RUNNER[pm]} stash eql install`)
      })
    })

    describe('precedence', () => {
      it('non-npm user agent wins over a mismatched lockfile', () => {
        const out = runWizard({
          lockfile: 'pnpm-lock.yaml',
          userAgent: 'bun/1.1.40 npm/? node/v22.3.0',
        })
        expect(out).toContain('Run: bunx stash eql install')
      })

      it('npm user agent is ignored in favour of a lockfile', () => {
        const out = runWizard({
          lockfile: 'bun.lock',
          userAgent: 'npm/10.2.4 node/v20.0.0',
        })
        expect(out).toContain('Run: bunx stash eql install')
      })
    })
  },
)

// Suite C — ensures that all built binaries render the correct runner prefix
// in their --help output when executed under different package manager environments.
describe('binaries — help text uses detected runner', () => {
  for (const pm of PMS) {
    for (const [name, bin] of Object.entries(BIN) as Array<
      [keyof typeof BIN, string]
    >) {
      it(`${name} --help renders ${RUNNER[pm]} for pm=${pm}`, () => {
        const result = spawnSync('node', [bin, '--help'], {
          env: { ...process.env, npm_config_user_agent: UA[pm] },
          encoding: 'utf8',
        })
        expect(
          result.status,
          `${name} --help (pm=${pm}) stderr: ${result.stderr}`,
        ).toBe(0)
        expect(result.stdout).toContain(RUNNER[pm])
        if (RUNNER[pm] !== 'npx') {
          expect(result.stdout).not.toMatch(/\bnpx\b/)
        }
      })
    }
  }
})
