import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import semver from 'semver'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'

// Supply-chain enforcement tests. Each `it` corresponds to a control
// from lirantal/npm-security-best-practices applied in this repo.
// See skills/stash-supply-chain-security/SKILL.md for the rationale and
// how to bypass any of these for legitimate reasons.

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(__dirname, '../..')

const read = (p: string) => readFileSync(join(REPO_ROOT, p), 'utf8')
const readJson = (p: string) => JSON.parse(read(p))
const readYaml = (p: string) => parseYaml(read(p))

// Map every package in the lockfile's `packages:` section to its resolved
// versions. Keys there are bare `name@version` (peer suffixes live under
// `snapshots:`), and scoped names keep their leading `@`, so split on the
// LAST `@`; strip any stray peer suffix defensively.
const resolvedVersionsByName = (): Map<string, string[]> => {
  const lock = readYaml('pnpm-lock.yaml') as {
    packages?: Record<string, unknown>
  }
  const byName = new Map<string, string[]>()
  for (const key of Object.keys(lock.packages ?? {})) {
    const at = key.lastIndexOf('@')
    if (at <= 0) continue // no scope-only or malformed keys
    const name = key.slice(0, at)
    const version = key.slice(at + 1).split('(')[0]
    const list = byName.get(name)
    if (list) list.push(version)
    else byName.set(name, [version])
  }
  return byName
}

describe('supply chain — pnpm configuration', () => {
  it('packageManager is pnpm ≥ 10.26 (needed for blockExoticSubdeps)', () => {
    const pm = readJson('package.json').packageManager as string
    expect(pm).toMatch(/^pnpm@/)
    const [maj, min] = pm.replace('pnpm@', '').split('.').map(Number)
    expect(maj).toBeGreaterThanOrEqual(10)
    if (maj === 10) expect(min).toBeGreaterThanOrEqual(26)
  })

  it('pnpm-workspace.yaml sets minimumReleaseAge ≥ 7 days', () => {
    // Enforce the configured policy (7 days), not just the lirantal minimum
    // (3 days). Mirrors the Dependabot cooldown so manual + automated
    // updates have the same community-discovery window.
    const ws = readYaml('pnpm-workspace.yaml') as { minimumReleaseAge?: number }
    expect(ws.minimumReleaseAge).toBeGreaterThanOrEqual(10080) // 7 days in minutes
  })

  it('pnpm-workspace.yaml sets blockExoticSubdeps: true', () => {
    const ws = readYaml('pnpm-workspace.yaml') as {
      blockExoticSubdeps?: boolean
    }
    expect(ws.blockExoticSubdeps).toBe(true)
  })

  it('onlyBuiltDependencies remains a small explicit allowlist (≤3 entries)', () => {
    const allow = (readJson('package.json').pnpm?.onlyBuiltDependencies ??
      []) as string[]
    expect(Array.isArray(allow)).toBe(true)
    expect(allow.length).toBeLessThanOrEqual(3)
  })

  it('minimumReleaseAgeExclude contains only first-party packages', () => {
    // The cooldown exclusion list exists for first-party packages that ship
    // on their own release cadence. Third-party security fixes must use the
    // one-off bypass (`pnpm install --config.minimum-release-age=0` with an
    // exact pin) instead — a name-scoped exclusion exempts every future
    // release of the package. See SKILL.md "Bypass the install cooldown".
    const ws = readYaml('pnpm-workspace.yaml') as {
      minimumReleaseAgeExclude?: string[]
    }
    const FIRST_PARTY = [/^@prisma-next\//, /^@cipherstash\//]
    for (const entry of ws.minimumReleaseAgeExclude ?? []) {
      expect(
        FIRST_PARTY.some((re) => re.test(entry)),
        `"${entry}" is not a first-party cooldown exclusion`,
      ).toBe(true)
    }
  })

  it('@cipherstash/auth and its six platform bindings are catalog-pinned in lockstep', () => {
    // Not tidiness — a load-bearing invariant. @cipherstash/auth pins its
    // bindings as EXACT-version optional peerDependencies, while stash /
    // stack / wizard declare the bindings in their own optionalDependencies
    // (pnpm doesn't auto-install optional peer deps). If the seven catalog
    // entries skew, npm nests per-consumer binding copies that the hoisted
    // auth package cannot resolve, and every project-local install of the
    // CLI/SDK dies at startup with "Failed to load native binding". That is
    // exactly what happened in 1.0.0-rc.2: Dependabot bumped the six
    // bindings to 0.42.0 while the ignored @cipherstash/auth stayed 0.41.0.
    // Dependabot now ignores all seven names; this test catches every other
    // way the set can drift.
    const ws = readYaml('pnpm-workspace.yaml') as {
      catalogs?: Record<string, Record<string, string>>
    }
    const repo = ws.catalogs?.repo ?? {}
    const authEntries = Object.entries(repo).filter(
      ([name]) =>
        name === '@cipherstash/auth' || name.startsWith('@cipherstash/auth-'),
    )
    // The wrapper + the six platform bindings. A count change means a
    // binding was added/removed upstream — update the consumers' package
    // JSONs and this expectation together.
    expect(authEntries.length).toBe(7)
    const versions = new Set(authEntries.map(([, v]) => v))
    expect(
      versions.size,
      `@cipherstash/auth* catalog entries have skewed versions: ${authEntries
        .map(([n, v]) => `${n}@${v}`)
        .join(', ')}`,
    ).toBe(1)
  })

  it('security overrides stay range-scoped and remain a small allowlist (≤12 entries)', () => {
    // Every override must be scoped to the advisory's vulnerable range
    // (`pkg@<range>`), never a blanket `pkg` pin — a blanket pin silently
    // rewrites versions outside the vulnerable range forever. The count cap
    // mirrors onlyBuiltDependencies: growth forces a conscious review.
    const ws = readYaml('pnpm-workspace.yaml') as {
      overrides?: Record<string, string>
    }
    const selectors = Object.keys(ws.overrides ?? {})
    expect(selectors.length).toBeLessThanOrEqual(12)
    for (const selector of selectors) {
      // A version-scoped selector has an `@` after the package name
      // (position > 0 handles `@scope/pkg@range`).
      expect(
        selector.lastIndexOf('@') > 0,
        `override "${selector}" is not scoped to a version range`,
      ).toBe(true)
    }
  })
})

describe('supply chain — registry pinning (.npmrc)', () => {
  it('pins @cipherstash scope and default registry to npmjs', () => {
    const npmrc = read('.npmrc')
    expect(npmrc).toMatch(
      /^@cipherstash:registry=https:\/\/registry\.npmjs\.org\/$/m,
    )
    expect(npmrc).toMatch(/^registry=https:\/\/registry\.npmjs\.org\/$/m)
  })

  it('does NOT contain auth tokens', () => {
    const npmrc = read('.npmrc')
    expect(npmrc).not.toMatch(/_authToken/i)
    expect(npmrc).not.toMatch(/NPM_TOKEN/)
  })
})

describe('supply chain — pnpm-lock.yaml integrity', () => {
  it('every resolved package comes from registry.npmjs.org (no git/tarball deps)', () => {
    const lock = readYaml('pnpm-lock.yaml') as {
      packages?: Record<
        string,
        { resolution?: { tarball?: string; type?: string } }
      >
    }
    const offenders: string[] = []
    for (const [name, entry] of Object.entries(lock.packages ?? {})) {
      const resolution = entry.resolution
      if (!resolution) continue
      // Workspace `link:` entries appear as `directory` — those are first-party,
      // not a supply-chain risk, and pnpm catalogs require them.
      if (resolution.type === 'directory') continue
      if (resolution.type === 'git') {
        offenders.push(`${name} (type=git)`)
        continue
      }
      const tarball = resolution.tarball
      if (tarball && !tarball.startsWith('https://registry.npmjs.org/')) {
        offenders.push(`${name} (tarball=${tarball})`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('every security override actually took effect (nothing left in a vulnerable range)', () => {
    // The shape test ("security overrides stay range-scoped") proves the
    // selectors are well-formed; this proves they *worked*. For each override
    // `selector -> target`, no package may resolve to a version that still
    // matches the vulnerable `selector` yet fails the `target` — that pair is
    // exactly a silent regression (e.g. a re-resolve demoting fast-uri below
    // its pin, un-fixing the advisory). Note `target` can sit inside its own
    // selector range (js-yaml@>=4.0.0 <5 -> 4.2.0 normalises all 4.x to the
    // patched release), so the check is "matched but not raised", not the
    // stricter "no version matches the selector".
    const ws = readYaml('pnpm-workspace.yaml') as {
      overrides?: Record<string, string>
    }
    const overrides = Object.entries(ws.overrides ?? {})
    // Guard the vacuous case: an empty/removed block would pass every loop
    // below with zero iterations.
    expect(overrides.length).toBeGreaterThan(0)

    const byName = resolvedVersionsByName()
    const offenders: string[] = []
    for (const [selector, target] of overrides) {
      const at = selector.lastIndexOf('@')
      const name = selector.slice(0, at)
      const vulnerableRange = selector.slice(at + 1)
      for (const version of byName.get(name) ?? []) {
        if (
          semver.satisfies(version, vulnerableRange) &&
          !semver.satisfies(version, target)
        ) {
          offenders.push(
            `${name}@${version} still matches vulnerable "${vulnerableRange}" (override target "${target}" not applied)`,
          )
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('package.json has no top-level `overrides` (pnpm only reads pnpm-workspace.yaml)', () => {
    // pnpm silently ignores a top-level npm-format `overrides` block; the
    // security pins must live in pnpm-workspace.yaml `overrides`. Guards
    // against the block being moved back here, where it would look applied
    // but do nothing.
    const pkg = readJson('package.json') as { overrides?: unknown }
    expect(pkg.overrides).toBeUndefined()
  })

  it('@anthropic-ai/sdk resolves to the peer-pinned patched version (≥ 0.106.0)', () => {
    // Not an override but a peer-resolution pin: packages/wizard depends on
    // @anthropic-ai/sdk@^0.106.0 to force the auto-installed peer of
    // @anthropic-ai/claude-agent-sdk past the advisory-vulnerable 0.81.0
    // (GHSA-p7fg-763f-g4gf). The override-effect test cannot cover a peer
    // pin, so assert the resolved version directly.
    const versions = resolvedVersionsByName().get('@anthropic-ai/sdk') ?? []
    expect(versions.length).toBeGreaterThan(0)
    for (const version of versions) {
      expect(
        semver.gte(version, '0.106.0'),
        `@anthropic-ai/sdk@${version} is below the patched 0.106.0`,
      ).toBe(true)
    }
  })
})

describe('supply chain — CI hardening (.github/workflows/tests.yml)', () => {
  const workflow = readYaml('.github/workflows/tests.yml') as {
    jobs: Record<
      string,
      {
        strategy?: { matrix?: Record<string, unknown> }
        steps: Array<{
          run?: string
          uses?: string
          with?: Record<string, unknown>
        }>
      }
    >
  }

  it('every `pnpm install` invocation uses --frozen-lockfile', () => {
    // Allow flag tokens (e.g. `pnpm --filter=foo install`, `pnpm -w install`)
    // between `pnpm` and `install`, but not arbitrary words — that would
    // false-match scripts like `pnpm run install-x`.
    const PNPM_INSTALL = /\bpnpm\b(?:\s+-{1,2}\S+)*\s+install\b/
    for (const [jobName, job] of Object.entries(workflow.jobs)) {
      const installSteps = job.steps.filter(
        (s) => typeof s.run === 'string' && PNPM_INSTALL.test(s.run),
      )
      for (const step of installSteps) {
        expect(step.run, `${jobName} step "${step.run}"`).toMatch(
          /--frozen-lockfile/,
        )
      }
    }
  })

  it('every pnpm-using job runs on Node 22 (literal or matrix incl. 22)', () => {
    for (const [jobName, job] of Object.entries(workflow.jobs)) {
      const usesPnpm = job.steps.some(
        (s) =>
          (typeof s.uses === 'string' &&
            s.uses.startsWith('pnpm/action-setup')) ||
          (typeof s.run === 'string' && /\bpnpm\b/.test(s.run)),
      )
      if (!usesPnpm) continue
      const setup = job.steps.find(
        (s) =>
          typeof s.uses === 'string' && s.uses.startsWith('actions/setup-node'),
      )
      expect(
        setup,
        `${jobName} uses pnpm but lacks actions/setup-node`,
      ).toBeTruthy()
      const nv = String(setup?.with?.['node-version'])
      if (nv === '22') continue
      // Allow `${{ matrix.<key> }}` only when that matrix key resolves to
      // an array of versions that includes 22 — so the matrix can broaden
      // coverage without ever dropping the Node 22 hardening baseline.
      const matrixRef = nv.match(/^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/)
      expect(
        matrixRef,
        `${jobName} node version: expected '22' or matrix expression, got '${nv}'`,
      ).toBeTruthy()
      const matrixKey = matrixRef![1]
      const versions = job.strategy?.matrix?.[matrixKey]
      expect(
        Array.isArray(versions),
        `${jobName} references matrix.${matrixKey} but no such array on strategy.matrix`,
      ).toBe(true)
      const versionStrings = (versions as unknown[]).map((v) => String(v))
      expect(
        versionStrings,
        `${jobName} matrix.${matrixKey} must include 22`,
      ).toContain('22')
    }
  })
})

describe('supply chain — automated dependency updates (Dependabot)', () => {
  const db = readYaml('.github/dependabot.yml') as {
    updates: Array<{
      'package-ecosystem': string
      cooldown?: { 'default-days'?: number; 'semver-major-days'?: number }
    }>
  }

  it('npm ecosystem has a ≥ 3 day cooldown', () => {
    const npm = db.updates.find((u) => u['package-ecosystem'] === 'npm')
    expect(npm).toBeDefined()
    expect(npm?.cooldown?.['default-days']).toBeGreaterThanOrEqual(3)
  })

  it('github-actions ecosystem is also covered with a ≥ 3 day cooldown', () => {
    const gha = db.updates.find(
      (u) => u['package-ecosystem'] === 'github-actions',
    )
    expect(gha).toBeDefined()
    expect(gha?.cooldown?.['default-days']).toBeGreaterThanOrEqual(3)
  })
})

describe('supply chain — governance (CODEOWNERS)', () => {
  it('protects supply-chain critical paths and assigns @cipherstash/developers', () => {
    // Substring-search comment lines too liberally — strip them first so a
    // bare comment mentioning the path can't satisfy the assertion.
    const rules = read('.github/CODEOWNERS')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'))

    for (const path of [
      'pnpm-workspace.yaml',
      'pnpm-lock.yaml',
      'dependabot.yml',
      '.npmrc',
      '.github/workflows/',
      // Composite actions run arbitrary steps inside the same job, with the
      // same secrets, as the workflow that calls them — same blast radius,
      // same review gate.
      '.github/actions/',
      '.github/CODEOWNERS',
      'skills/stash-supply-chain-security/',
    ]) {
      const rule = rules.find((l) => l.includes(path))
      expect(rule, `no CODEOWNERS rule covers ${path}`).toBeDefined()
      const owners = rule!.split(/\s+/).slice(1)
      expect(owners, `${path} CODEOWNERS owners`).toContain(
        '@cipherstash/developers',
      )
    }
  })
})
