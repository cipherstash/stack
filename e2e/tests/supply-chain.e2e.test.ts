import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
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
    const ws = readYaml('pnpm-workspace.yaml') as { blockExoticSubdeps?: boolean }
    expect(ws.blockExoticSubdeps).toBe(true)
  })

  it('onlyBuiltDependencies remains a small explicit allowlist (≤3 entries)', () => {
    const allow = (readJson('package.json').pnpm?.onlyBuiltDependencies ?? []) as string[]
    expect(Array.isArray(allow)).toBe(true)
    expect(allow.length).toBeLessThanOrEqual(3)
  })
})

describe('supply chain — registry pinning (.npmrc)', () => {
  it('pins @cipherstash scope and default registry to npmjs', () => {
    const npmrc = read('.npmrc')
    expect(npmrc).toMatch(/^@cipherstash:registry=https:\/\/registry\.npmjs\.org\/$/m)
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
      packages?: Record<string, { resolution?: { tarball?: string; type?: string } }>
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
})

describe('supply chain — CI hardening (.github/workflows/tests.yml)', () => {
  const workflow = readYaml('.github/workflows/tests.yml') as {
    jobs: Record<
      string,
      {
        strategy?: { matrix?: Record<string, unknown> }
        steps: Array<{ run?: string; uses?: string; with?: Record<string, unknown> }>
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
        expect(step.run, `${jobName} step "${step.run}"`).toMatch(/--frozen-lockfile/)
      }
    }
  })

  it('every pnpm-using job runs on Node 22 (literal or matrix incl. 22)', () => {
    for (const [jobName, job] of Object.entries(workflow.jobs)) {
      const usesPnpm = job.steps.some(
        (s) =>
          (typeof s.uses === 'string' && s.uses.startsWith('pnpm/action-setup')) ||
          (typeof s.run === 'string' && /\bpnpm\b/.test(s.run)),
      )
      if (!usesPnpm) continue
      const setup = job.steps.find(
        (s) => typeof s.uses === 'string' && s.uses.startsWith('actions/setup-node'),
      )
      expect(setup, `${jobName} uses pnpm but lacks actions/setup-node`).toBeTruthy()
      const nv = String(setup?.with?.['node-version'])
      if (nv === '22') continue
      // Allow `${{ matrix.<key> }}` only when that matrix key resolves to
      // an array of versions that includes 22 — so the matrix can broaden
      // coverage without ever dropping the Node 22 hardening baseline.
      const matrixRef = nv.match(/^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/)
      expect(matrixRef, `${jobName} node version: expected '22' or matrix expression, got '${nv}'`).toBeTruthy()
      const matrixKey = matrixRef![1]
      const versions = job.strategy?.matrix?.[matrixKey]
      expect(
        Array.isArray(versions),
        `${jobName} references matrix.${matrixKey} but no such array on strategy.matrix`,
      ).toBe(true)
      const versionStrings = (versions as unknown[]).map((v) => String(v))
      expect(versionStrings, `${jobName} matrix.${matrixKey} must include 22`).toContain('22')
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
    const gha = db.updates.find((u) => u['package-ecosystem'] === 'github-actions')
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
      '.github/CODEOWNERS',
      'skills/stash-supply-chain-security/',
    ]) {
      const rule = rules.find((l) => l.includes(path))
      expect(rule, `no CODEOWNERS rule covers ${path}`).toBeDefined()
      const owners = rule!.split(/\s+/).slice(1)
      expect(owners, `${path} CODEOWNERS owners`).toContain('@cipherstash/developers')
    }
  })
})
