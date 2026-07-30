import { readdirSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { INTEGRATION_ADAPTER_PACKAGES } from '../commands/init/steps/install-deps.js'
import {
  RELEASE_TRAIN_MANIFESTS,
  type ReleaseTrainPackage,
} from '../release-train.js'

const CLI_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const REPO_ROOT = resolve(CLI_ROOT, '../..')
const SKILLS_ROOT = resolve(REPO_ROOT, 'skills')

/** The stable version a workspace manifest belongs to: `1.0.0-rc.4` → `1.0.0`. */
function stableVersion(version: string): string {
  return version.split('-')[0] as string
}

function isReleaseTrainPackage(pkg: string): pkg is ReleaseTrainPackage {
  return Object.hasOwn(RELEASE_TRAIN_MANIFESTS, pkg)
}

function manifestVersion(pkg: ReleaseTrainPackage): string {
  const rel = RELEASE_TRAIN_MANIFESTS[pkg]
  if (!rel) throw new Error(`${pkg} is not on the release train`)
  const manifest = JSON.parse(readFileSync(resolve(CLI_ROOT, rel), 'utf8')) as {
    version: string
  }
  return manifest.version
}

// The growth guard for #661: `RELEASE_TRAIN_MANIFESTS` is the single source
// the build embeds versions from, and `INTEGRATION_ADAPTER_PACKAGES` is what
// init installs. An adapter present in the second but absent from the first
// would install UNPINNED and be invisible to the skew warning — silently
// reintroducing the dist-tag failure mode on exactly the newest package. This
// suite turns that omission into a red test.
describe('release train coverage', () => {
  it('every integration adapter package rides the release train', () => {
    for (const pkg of Object.values(INTEGRATION_ADAPTER_PACKAGES)) {
      expect(
        RELEASE_TRAIN_MANIFESTS,
        `${pkg} is installed by init but missing from RELEASE_TRAIN_MANIFESTS — it would install unpinned`,
      ).toHaveProperty([pkg])
    }
  })

  it('the core packages and every one-shot-executed package are on the train', () => {
    // stash: init self-installs it; @cipherstash/stack: the client;
    // @cipherstash/wizard: EXECUTED via `npx` from `stash wizard` / the impl
    // handoff, so an unpinned run would execute a different release.
    for (const pkg of ['stash', '@cipherstash/stack', '@cipherstash/wizard']) {
      expect(RELEASE_TRAIN_MANIFESTS).toHaveProperty([pkg])
    }
  })

  it('pins the bare-project stash invocation in the published CLI skill', () => {
    const skill = readFileSync(
      resolve(SKILLS_ROOT, 'stash-cli/SKILL.md'),
      'utf8',
    )

    // The pin names the STABLE version of this release line, not the raw
    // manifest version: the skill is read in a customer's repo against what is
    // published, and a prerelease build's own `1.0.0-rc.4` would tell them to
    // run a release candidate in production (#791).
    expect(skill).toContain(
      `npx --package=stash@${stableVersion(manifestVersion('stash'))} stash eql install --database-url 'postgres://...'`,
    )
  })

  // #791: `skills/` ships inside the `stash` tarball and is copied into
  // customer repos by `stash init`, and NOTHING in the build rewrites the
  // version literals inside it — `tsup.config.ts` copies the directory
  // verbatim, and the `__STASH_RUNTIME_VERSIONS__` embed only reaches compiled
  // CLI code. So a hardcoded `@cipherstash/stack@1.0.0-rc.4` would keep telling
  // Deno and Supabase Edge users to pin a release candidate long after the
  // stable release. This is the guard: it fires on the version-bump PR, when
  // someone is in a position to update the surrounding prose too.
  describe('skill version pins', () => {
    const skillFiles = readdirSync(SKILLS_ROOT, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => ({
        skill: entry.name,
        body: readFileSync(
          resolve(SKILLS_ROOT, entry.name, 'SKILL.md'),
          'utf8',
        ),
      }))

    it('finds skills to check (a moved directory must not silently pass)', () => {
      expect(skillFiles.length).toBeGreaterThan(0)
    })

    it.each(
      skillFiles,
    )('$skill pins release-train packages at a stable version on the current major', ({
      body,
    }) => {
      // Exact pins only (`pkg@1.2.3`, optionally `npm:`-prefixed and with a
      // trailing subpath). A range spec (`^1.0.0`) carries its own semantics
      // and is not a pin to check.
      const PIN =
        /(?:npm:)?(stash|@cipherstash\/[a-z0-9-]+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/g

      for (const [, pkg, pinned] of body.matchAll(PIN)) {
        if (!isReleaseTrainPackage(pkg)) continue
        const current = manifestVersion(pkg)

        expect(
          pinned,
          `${pkg}@${pinned} pins a prerelease — skills ship to customers, so pin the stable release (${stableVersion(current)})`,
        ).not.toContain('-')

        expect(
          pinned.split('.')[0],
          `${pkg}@${pinned} is off this release line (${current}) — update the pin and the prose around it`,
        ).toBe(stableVersion(current).split('.')[0])
      }
    })
  })

  it('every train manifest exists and carries a version (what tsup will embed)', () => {
    // Exercises the exact inputs tsup.config.ts reads at build time, so a
    // renamed/moved workspace package fails HERE in source-mode tests, not
    // only at the next build.
    for (const [pkg, rel] of Object.entries(RELEASE_TRAIN_MANIFESTS)) {
      const manifest: unknown = JSON.parse(
        readFileSync(resolve(CLI_ROOT, rel), 'utf8'),
      )
      const m = manifest as { name?: unknown; version?: unknown }
      expect(m.name, `${rel} package name`).toBe(pkg)
      expect(typeof m.version, `${pkg} version`).toBe('string')
      expect((m.version as string).length).toBeGreaterThan(0)
    }
  })

  it('the changesets fixed group is exactly the release train (staleness guard)', () => {
    // The staleness half of #661/#669 is release-process config: every train
    // package must version in lockstep with `stash`, or a release of the odd
    // one out ships while the published CLI still embeds — and pins — its old
    // version. Guard the config like the code: group membership must equal
    // the train, exactly.
    const config = JSON.parse(
      readFileSync(resolve(REPO_ROOT, '.changeset/config.json'), 'utf8'),
    ) as { fixed?: string[][] }
    const group = config.fixed?.find((g) => g.includes('stash'))
    expect(group, 'a changesets fixed group containing stash').toBeDefined()
    expect(new Set(group)).toEqual(
      new Set(Object.keys(RELEASE_TRAIN_MANIFESTS)),
    )
  })
})
