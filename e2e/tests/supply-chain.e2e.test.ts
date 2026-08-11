import { execFileSync } from 'node:child_process'
import { existsSync, globSync, readdirSync, readFileSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
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

describe('supply chain — every workflow installs with --frozen-lockfile', () => {
  /**
   * The rule is "CI uses `pnpm install --frozen-lockfile`", and it was checked
   * in one workflow. `release.yml` — the one workflow that publishes to npm —
   * ran a bare `pnpm install` from the day it was written, so the single
   * install permitted to resolve outside the lockfile was the one whose output
   * goes to the registry. A lockfile-free install there can pick up a version
   * nobody reviewed and publish artifacts built against it.
   *
   * Scanned across the directory, and through local composite actions, for the
   * same reason the caching gate is: `.github/actions/integration-setup`
   * installs on behalf of four jobs, and a rule that stops at the workflow file
   * makes "move it into a composite" the way around it.
   */
  /**
   * `pnpm … install` / `pnpm … i` as a whole token.
   *
   * The `i` alternative is not decoration: `scripts/__tests__/workflow-node-gyp.test.mjs`
   * matches it and pins `pnpm i --frozen-lockfile` as a spelling this repo uses,
   * so a narrower pattern here would leave the two guards disagreeing about what
   * an install IS — the node-gyp rule would cover a `pnpm i` step and this one
   * would not.
   */
  const PNPM_INSTALL = /(?:^|[\s;&|(])pnpm\s+(?:[^\n]*\s)?(?:install|i)(?:\s|$)/

  /**
   * A step's `run:` body as the commands it actually runs, one per entry.
   *
   * PER COMMAND, not per step, and the difference is a real hole rather than a
   * refinement: a step holding both `pnpm install` and, later,
   * `pnpm install --frozen-lockfile` satisfies a whole-body search for the flag
   * while still running the unpinned install.
   *
   * A NEWLINE IS NOT WHAT SEPARATES TWO COMMANDS — shell separators do, and
   * splitting on newlines alone left `pnpm install; pnpm install
   * --frozen-lockfile` as one "command" carrying the flag, which is the same
   * defect one level down. `;`, `&&`, `||`, `|` and a trailing `&` all start a
   * new command, so all of them split.
   *
   * The split is quote-blind: `echo "pnpm install; ok"` becomes two fragments.
   * That is a false POSITIVE at worst — a reported offender that is not one —
   * and the pattern was already quote-blind before this, since it matched
   * `pnpm install` inside an `echo` just the same. Fail-closed is the right
   * direction here.
   *
   * Backslash continuations are joined first, so an install whose flag sits on
   * the next line is still one command and still passes.
   */
  const commandsOf = (run: string): string[] =>
    run
      .replace(/\\\r?\n\s*/g, ' ')
      .split(/\r?\n|;|&&|\|\||\||&/)
      .map((fragment) => fragment.trim())
      .filter((fragment) => fragment !== '' && !fragment.startsWith('#'))

  /**
   * The installs in one `run:` body that resolve outside the lockfile.
   *
   * One definition, used by both the property test and the repo sweep below —
   * two copies of the predicate would let the test pin a rule the sweep no
   * longer applies.
   */
  const unpinnedInstalls = (run: string): string[] =>
    commandsOf(run).filter(
      (command) =>
        PNPM_INSTALL.test(command) && !/--frozen-lockfile\b/.test(command),
    )

  const stepsOf = (relPath: string): Array<{ run?: string }> => {
    const doc = readYaml(relPath) as {
      jobs?: Record<string, { steps?: Array<{ run?: string }> }>
      runs?: { steps?: Array<{ run?: string }> }
    }
    return [
      ...Object.values(doc?.jobs ?? {}).flatMap((job) => job?.steps ?? []),
      ...(doc?.runs?.steps ?? []),
    ]
  }

  const files = [
    ...globSync('.github/workflows/*.{yml,yaml}', { cwd: REPO_ROOT }),
    // `**` because a composite action does not have to sit one level down:
    // `uses: ./.github/actions/group/name` is valid, and the flat glob that
    // covers today's four would silently stop covering a grouped one. Workflows
    // stay flat on purpose — GitHub reads `.github/workflows/*` and does not
    // descend, so a nested file there is not a workflow at all.
    ...globSync('.github/actions/**/action.{yml,yaml}', { cwd: REPO_ROOT }),
  ].sort()

  it('scans every workflow GitHub reads, with no slack', () => {
    // Equality against the directory, not a floor with room in it: a
    // `length > N` guard lets N files drop out of the scan before anything
    // notices, and this repo has already been bitten by that shape (see the
    // mutation note in scripts/__tests__/ffi-binding-step-order.test.mjs). The
    // offender check below is one aggregated assertion, so a file falling out
    // of `files` does not delete a visible test — it silently narrows this one.
    const workflows = readdirSync(join(REPO_ROOT, '.github/workflows'))
      .filter((name) => /\.ya?ml$/.test(name))
      .map((name) => `.github/workflows/${name}`)
      .sort()
    expect(files.filter((f) => f.startsWith('.github/workflows/'))).toEqual(
      workflows,
    )
    // The composite half cannot be compared to a directory listing the same
    // way — `.github/actions/*` holds directories, not manifests — so it gets
    // the floor the other half no longer needs.
    expect(files).toContain('.github/actions/integration-setup/action.yml')
  })

  it('reads one command at a time, so a later flag cannot cover an earlier install', () => {
    // The property, pinned against synthetic input rather than against the
    // repo: a repo that happens to be clean says nothing about how strict the
    // checker is. A step holding both installs is the shape a whole-body search
    // for the flag waves through.
    expect(
      unpinnedInstalls('pnpm install\npnpm install --frozen-lockfile'),
    ).toEqual(['pnpm install'])

    // A continuation is one command, not two, so the flag on the next line
    // still counts.
    expect(unpinnedInstalls('pnpm install \\\n  --frozen-lockfile')).toEqual([])

    // A comment naming the flag is not the flag.
    expect(
      unpinnedInstalls('# always --frozen-lockfile\npnpm install'),
    ).toEqual(['pnpm install'])

    // `pnpm i` is an install. The node-gyp guard already treats it as one.
    expect(unpinnedInstalls('pnpm i')).toEqual(['pnpm i'])
    expect(unpinnedInstalls('pnpm i --frozen-lockfile')).toEqual([])

    // …and `pnpm run install-x` is not, despite containing the word.
    expect(unpinnedInstalls('pnpm run install-deps')).toEqual([])
  })

  it('splits shell separators, so one line cannot hide an unpinned install', () => {
    // The same defect as the multi-line case, one level down. Splitting on
    // newlines alone leaves `pnpm install; pnpm install --frozen-lockfile` as a
    // single "command" that contains the flag — so the guard reports nothing
    // while the first install resolves outside the lockfile. A `run:` block is
    // shell, and shell does not need a newline to run two commands.
    expect(
      unpinnedInstalls('pnpm install; pnpm install --frozen-lockfile'),
    ).toEqual(['pnpm install'])

    // Every separator that starts a new command, not just `;`.
    expect(
      unpinnedInstalls('pnpm install --frozen-lockfile && pnpm install'),
    ).toEqual(['pnpm install'])
    expect(
      unpinnedInstalls('pnpm i || pnpm install --frozen-lockfile'),
    ).toEqual(['pnpm i'])
    expect(unpinnedInstalls('echo start | pnpm install')).toEqual([
      'pnpm install',
    ])

    // A pinned install keeps passing when it shares a line with other work —
    // the split must not turn the flag into a different command from the
    // install it belongs to.
    expect(
      unpinnedInstalls(
        'echo start && pnpm install --frozen-lockfile && echo done',
      ),
    ).toEqual([])
  })

  it('carries --frozen-lockfile on every install', () => {
    const offenders = files.flatMap((file) =>
      stepsOf(file)
        .filter((step) => typeof step.run === 'string')
        .flatMap((step) =>
          unpinnedInstalls(step.run as string).map(
            (command) => `${file}: ${command}`,
          ),
        ),
    )
    expect(
      offenders,
      'A CI install that is not `--frozen-lockfile` resolves versions the lockfile does not name, with no review and no record.',
    ).toEqual([])
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

  // The `--frozen-lockfile` check that used to live here is gone, not moved by
  // accident: the describe above supersedes it in both directions — every
  // workflow and composite rather than this one file, and per command rather
  // than per step body. Keeping the narrower copy would be worse than
  // redundant, because it PASSES on inputs the broader one fails, so a reader
  // who found it first would get a wrong answer about what this repo enforces.

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

// Every path git considers part of the repo: tracked files, plus untracked
// ones that are not ignored, so a lockfile added in the working tree fails
// here before it reaches CI. `--exclude-standard` is what keeps node_modules,
// dist/, target/ and every other generated path out of the scan — hand-rolling
// that skip list is how a scan silently starts missing things.
const repoFiles = (): string[] =>
  execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  )
    .split('\0')
    .filter((p) => p.length > 0)

// What a lockfile *looks like*, matched on shape rather than on a closed list
// of names. This is the load-bearing half of the coverage test below: the
// failure it exists to catch is a lockfile for a language nobody thought
// about, and a name-only list is blind to exactly that case.
const LOCKFILE_SHAPES = [
  /\.lock$/i, // Cargo.lock, yarn.lock, poetry.lock, uv.lock, deno.lock
  /\.lockb$/i, // bun.lockb
  /\.lockfile$/i, // gradle.lockfile
  /-lock\.(json|ya?ml)$/i, // package-lock.json, pnpm-lock.yaml
  /\.lock\.json$/i, // packages.lock.json (NuGet)
  /^go\.sum$/, // Go has no ".lock" convention
  /^npm-shrinkwrap\.json$/,
]
const looksLikeLockfile = (name: string) =>
  LOCKFILE_SHAPES.some((re) => re.test(name))

// Lockfile basename -> the `package-ecosystem` value Dependabot monitors it
// with. Deliberately broader than what the repo contains today: the point is
// that adding a lockfile is enough to make the test demand its entry, without
// anyone having to remember to teach the test about the new ecosystem first.
const ECOSYSTEM_BY_LOCKFILE: Record<string, string> = {
  'pnpm-lock.yaml': 'npm',
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'yarn.lock': 'npm',
  'bun.lock': 'bun',
  'bun.lockb': 'bun',
  'Cargo.lock': 'cargo',
  'go.sum': 'gomod',
  'Gemfile.lock': 'bundler',
  'composer.lock': 'composer',
  'Pipfile.lock': 'pip',
  'poetry.lock': 'pip',
  'uv.lock': 'uv',
  'mix.lock': 'mix',
  'pubspec.lock': 'pub',
  'packages.lock.json': 'nuget',
  'gradle.lockfile': 'gradle',
}

// Lockfiles Dependabot cannot monitor at all, because no `package-ecosystem`
// covers them. Keyed by basename because that is what the exemption is really
// about — a property of Dependabot's ecosystem list, not of where the file
// sits. Naming them here with a reason keeps the gap reviewable instead of
// filtering it out silently.
const NO_DEPENDABOT_ECOSYSTEM: Record<string, string> = {
  // e2e/wasm/deno.lock — JSR specifiers (@std/assert). Dependabot has no Deno
  // or JSR ecosystem. The suite pins nothing from npm (see e2e/wasm/deno.json:
  // every import resolves to a file pnpm already installed), so the versions
  // that matter are covered by pnpm-lock.yaml.
  'deno.lock': 'Deno/JSR is not a Dependabot ecosystem',
  // .flox/env/manifest.lock — Flox (Nix) dev-environment lock: node, pnpm,
  // 1password CLI. A toolchain pin, not an application dependency tree, and
  // Nixpkgs is not a Dependabot ecosystem.
  'manifest.lock': 'Flox/Nix environment lock, not a dependency ecosystem',
}

// Where each ecosystem's *manifest* lives, so a `directory` can be checked for
// actually pointing at one. Dependabot reports a misaimed directory only in the
// repo's Dependabot log page, which nobody reads — the visible symptom is
// simply no PRs, forever.
const MANIFEST_BY_ECOSYSTEM: Record<string, string> = {
  npm: 'package.json',
  bun: 'package.json',
  cargo: 'Cargo.toml',
  gomod: 'go.mod',
  bundler: 'Gemfile',
  composer: 'composer.json',
  uv: 'pyproject.toml',
  mix: 'mix.exs',
  pub: 'pubspec.yaml',
  // github-actions is special-cased: Dependabot requires `directory: /` and
  // discovers .github/workflows itself.
  'github-actions': '.github/workflows',
}

type DependabotUpdate = {
  'package-ecosystem': string
  directory?: string
  directories?: string[]
  cooldown?: { 'default-days'?: number; 'semver-major-days'?: number }
  ignore?: Array<{ 'dependency-name'?: string; 'update-types'?: string[] }>
}

// Does this entry refuse major version updates across the board? That is the
// blanket `dependency-name: "*"` rule, not a per-package one — a named
// dependency's major can be ignored for its own reasons without saying
// anything about the entry's policy.
const ignoresAllSemverMajor = (entry: DependabotUpdate): boolean =>
  (entry.ignore ?? []).some(
    (rule) =>
      rule['dependency-name'] === '*' &&
      (rule['update-types'] ?? []).includes('version-update:semver-major'),
  )

// Which of an entry's configured locations resolve to no manifest at all —
// i.e. monitor nothing.
//
// The two keys are checked differently on purpose. Dependabot's options
// reference says: "The `directories` key supports globbing and the wildcard
// character `*`. These features are not supported by the `directory` key." So a
// `*` written under the singular `directory` is a literal path segment to
// Dependabot — an entry that monitors nothing, which is exactly the failure
// this check exists to catch — and glob-expanding it here would hide it.
//
// A glob is satisfied by matching AT LEAST ONE directory holding the manifest,
// not all of them. `/packages/*` under the npm entry would fail an every-match
// rule against this very tree today: packages/utils/ holds only config/ and
// logger/, with no package.json of its own.
//
// Expanded with node:fs `globSync` (Node 22, which package.json engines already
// require) rather than a glob library — this package has none, and a check on
// dependency policy is a poor place to add a dependency.
const unmonitoredDirectories = (
  entry: Pick<DependabotUpdate, 'directory' | 'directories'>,
  manifest: string,
): string[] => {
  const globbed = entry.directories !== undefined
  const failures: string[] = []

  // `directories: []` monitors nothing, and the loop below would report
  // nothing about it — it has no iteration to fail on. That is the same
  // "configured to watch a location Dependabot finds no manifest in" defect
  // the rest of this function exists to catch, arriving as an absence rather
  // than a wrong value, so it has to be named separately.
  if (entry.directories?.length === 0) {
    return ['`directories` is empty, so this entry monitors nothing']
  }

  for (const dir of entry.directories ?? [entry.directory ?? '/']) {
    // Dependabot paths are repo-root-relative with a leading slash; strip it
    // rather than letting join()/glob read them as absolute.
    const prefix = dir.replace(/^\/+/, '')
    const found = globbed
      ? globSync(prefix ? `${prefix}/${manifest}` : manifest, {
          cwd: REPO_ROOT,
        }).length > 0
      : existsSync(join(REPO_ROOT, prefix, manifest))
    if (found) continue
    failures.push(
      globbed
        ? `"${dir}" matches no directory containing a ${manifest}`
        : `"${dir}" contains no ${manifest}`,
    )
  }
  return failures
}

describe('supply chain — automated dependency updates (Dependabot)', () => {
  const db = readYaml('.github/dependabot.yml') as {
    updates: DependabotUpdate[]
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

  it('every entry ignores majors, so none configures a major cooldown window', () => {
    // One relationship, asserted from both ends, because either end alone
    // passes on the drift that matters.
    //
    // `semver-major-days` delays major VERSION update PRs. Every entry here
    // ignores `version-update:semver-major` for `*`, so no major version
    // update is ever proposed for it to delay — and it cannot reach the
    // security path instead, because "the cooldown option is only available
    // for version updates, not security updates" (Dependabot options
    // reference). A major window is therefore dead config, and dead config
    // reads as policy to the next person: it says majors arrive after 14
    // days, when in fact they never arrive. Same judgement the cargo entry
    // records for the `day:` key it leaves out of a monthly schedule.
    //
    // Asserting only "if it ignores majors then no window" would pass
    // vacuously on exactly the change that makes a window live again —
    // dropping the ignore. So the ignore is pinned too, which also gives the
    // control documented in skills/stash-supply-chain-security its first
    // test: majors are reviewed and applied by hand, never proposed.
    expect(db.updates.length).toBeGreaterThan(0) // no entries, no iterations
    for (const entry of db.updates) {
      const ecosystem = entry['package-ecosystem']
      expect(
        ignoresAllSemverMajor(entry),
        `${ecosystem} no longer ignores "version-update:semver-major" for "*" — majors are meant to be applied by hand, and dropping this makes a cooldown window meaningful again`,
      ).toBe(true)
      expect(
        entry.cooldown?.['semver-major-days'],
        `${ecosystem} sets a semver-major cooldown window while ignoring major version updates — the key delays PRs that are never opened`,
      ).toBeUndefined()
    }
  })

  it('every lockfile in the tree has a package-ecosystem entry', () => {
    // Derived from the filesystem, not from a list of ecosystems we expect —
    // so the NEXT lockfile someone adds (a new language, a nested manifest)
    // fails here instead of quietly going unmonitored. Absorbing
    // packages/protect-ffi is precisely that event: it brought a 494-crate
    // Cargo.lock in-tree, which osv-scanner already scans for known
    // advisories (`--recursive ./` reaches it) while nothing proposed the
    // routine version bumps.
    //
    // Coverage is asserted per ECOSYSTEM, not per directory. Dependabot's npm
    // entry at `/` follows the pnpm workspace, which does not include
    // packages/protect-ffi/integration-tests — that lockfile therefore sits
    // under a monitored ecosystem but is not itself updated. Deliberate: it is
    // a standalone `npm install` harness with no published surface, and its
    // advisories are still visible via osv-scanner.
    const ecosystems = new Set(db.updates.map((u) => u['package-ecosystem']))
    const unmonitored: string[] = []
    const unrecognised: string[] = []
    let matched = 0

    for (const file of repoFiles()) {
      const name = basename(file)
      if (!looksLikeLockfile(name)) continue
      if (name in NO_DEPENDABOT_ECOSYSTEM) continue
      const ecosystem = ECOSYSTEM_BY_LOCKFILE[name]
      if (!ecosystem) {
        unrecognised.push(file)
        continue
      }
      matched++
      if (!ecosystems.has(ecosystem)) {
        unmonitored.push(`${file} needs \`package-ecosystem: ${ecosystem}\``)
      }
    }

    // Guard the vacuous case: a scan that finds nothing passes every loop.
    // pnpm-lock.yaml alone makes this non-zero.
    expect(matched).toBeGreaterThan(0)
    expect(
      unrecognised,
      'lockfile with no known ecosystem — add it to ECOSYSTEM_BY_LOCKFILE, or to NO_DEPENDABOT_ECOSYSTEM with the reason Dependabot cannot monitor it',
    ).toEqual([])
    expect(
      unmonitored,
      'lockfile present in the repo with no Dependabot ecosystem monitoring it',
    ).toEqual([])
  })

  it("every entry's directory contains the manifest its ecosystem reads", () => {
    // The other half of coverage: an entry naming the right ecosystem but the
    // wrong directory monitors nothing, and fails silently — Dependabot logs
    // "no manifest found" on a page nobody visits, and the symptom is just an
    // absence of PRs. Load-bearing for cargo, whose workspace root is
    // packages/protect-ffi, not the repo root.
    for (const entry of db.updates) {
      const ecosystem = entry['package-ecosystem']
      const manifest = MANIFEST_BY_ECOSYSTEM[ecosystem]
      expect(
        manifest,
        `unknown ecosystem "${ecosystem}" — add its manifest filename to MANIFEST_BY_ECOSYSTEM`,
      ).toBeDefined()
      expect(
        unmonitoredDirectories(entry, manifest),
        `${ecosystem} entry is configured to watch a location Dependabot will find no ${manifest} in`,
      ).toEqual([])
    }
  })

  it('a `directories` glob is expanded; the same pattern under `directory` is not', () => {
    // No entry in .github/dependabot.yml uses `directories` today, so the glob
    // branch above ships with no live coverage — and the first person to write
    // `directories: ["/packages/*"]` would otherwise be failed by a check
    // reporting "no package.json" at a path that was never meant to be literal.
    // Synthetic entries because this suite asserts against the real config as
    // committed; exercising a branch must not mean editing it.
    expect(
      unmonitoredDirectories({ directories: ['/packages/*'] }, 'package.json'),
    ).toEqual([])
    // Literal paths remain valid under `directories` — globbing is an
    // extension of the key, not a requirement of it.
    expect(
      unmonitoredDirectories({ directories: ['/e2e'] }, 'package.json'),
    ).toEqual([])
    // The repo root, which is where both live entries point. It is the one
    // input that reaches the empty-`prefix` half of the pattern above, and it
    // needs it: `/package.json` is ABSOLUTE to globSync and matches nothing,
    // so joining a bare manifest onto an empty prefix reports the repo root
    // as monitoring nothing. Splicing that branch out leaves every other
    // assertion in this block green — this is the only one that fails.
    expect(
      unmonitoredDirectories({ directories: ['/'] }, 'package.json'),
    ).toEqual([])
    // The point of the check survives globbing: a pattern matching nothing is
    // still an entry that monitors nothing.
    expect(
      unmonitoredDirectories({ directories: ['/no-such-*'] }, 'package.json'),
    ).toHaveLength(1)
    // Dependabot does not expand `directory`, so neither does this — a glob
    // written there monitors nothing and must fail even though the identical
    // pattern passes above.
    expect(
      unmonitoredDirectories({ directory: '/packages/*' }, 'package.json'),
    ).toHaveLength(1)
    // An empty list fails too. It has no entry to be wrong about, so a
    // per-directory check reports nothing and the entry passes while
    // monitoring nothing — the failure this whole block exists to catch,
    // arriving as an absence.
    expect(
      unmonitoredDirectories({ directories: [] }, 'package.json'),
    ).toHaveLength(1)
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
