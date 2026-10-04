import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The root `release-plz.toml` must name every member of the root Cargo
 * workspace, and say which of them release.
 *
 * `publish = false` in a crate's manifest stops `release-plz release` from
 * uploading it, but not `release-plz update` from bumping its version and
 * writing its changelog. So the published crates are each in a named
 * `version_group` (`stack-auth` and `stack-profile` in one, `stack-kms`,
 * `stack-encrypt` and `stack-encrypt-derive` in another), and every other
 * member carries `release = false`. A member added to the workspace without a line here would
 * be versioned on the next release-plz run.
 *
 * Each of those members also carries `publish = false`. The workspace table
 * sets `publish = true`, and release-plz applies it to every package that
 * does not set its own. `release-plz release` then exits before publishing
 * anything: "Package `stack-kms` has `publish = false` or `publish = []` in
 * the Cargo.toml, but it has `publish = true` in the release-plz
 * configuration."
 *
 * `cargo-publish-opt-out.test.mjs` pins which members may publish; this pins
 * that the release-plz configuration agrees with it.
 */

const WORKFLOW = '.github/workflows/release-plz.yml'
const CONFIG = 'release-plz.toml'
// Each published crate, and the version group it releases in.
const GROUPS = {
  'stack-auth': 'stack-auth',
  'stack-profile': 'stack-auth',
  'stack-kms': 'stack-encrypt',
  'stack-encrypt': 'stack-encrypt',
  'stack-encrypt-derive': 'stack-encrypt',
}
const PUBLISHED = Object.keys(GROUPS).sort()

/** The root workspace's members, as `{ path, name, publish }`. */
function rootMembers() {
  const manifest = readFileSync(join(REPO_ROOT, 'Cargo.toml'), 'utf8')
  const block = /^members\s*=\s*\[([^\]]*)\]/m.exec(manifest)?.[1] ?? ''
  return [...block.matchAll(/"([^"]+)"/g)].map(([, path]) => {
    const crate = readFileSync(join(REPO_ROOT, path, 'Cargo.toml'), 'utf8')
    return {
      path,
      name: /^name\s*=\s*"([^"]+)"/m.exec(crate)?.[1],
      publish: !/^publish\s*=\s*false$/m.test(crate),
    }
  })
}

/** `[[package]]` tables of release-plz.toml, keyed by name. */
function configuredPackages(source) {
  const packages = new Map()
  for (const table of source.split(/^\[\[package\]\]$/m).slice(1)) {
    const body = table.split(/^\[/m)[0]
    const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1]
    packages.set(name, {
      versionGroup: /^version_group\s*=\s*"([^"]+)"/m.exec(body)?.[1] ?? null,
      release: !/^release\s*=\s*false$/m.test(body),
      publish: !/^publish\s*=\s*false$/m.test(body),
    })
  }
  return packages
}

const source = readFileSync(join(REPO_ROOT, CONFIG), 'utf8')
const members = rootMembers()
const packages = configuredPackages(source)

describe('root release-plz.toml', () => {
  it('finds the workspace members it means to check', () => {
    // A members list this cannot read must fail, not pass on nothing.
    expect(members.map((member) => member.name)).toEqual(
      expect.arrayContaining(PUBLISHED),
    )
    expect(members.every((member) => member.name)).toBe(true)
  })

  it('names every root workspace member, and nothing else', () => {
    expect([...packages.keys()].sort()).toEqual(
      members.map((member) => member.name).sort(),
    )
  })

  it('releases exactly the crates that may publish, each in its version group', () => {
    const publishable = members
      .filter((member) => member.publish)
      .map((member) => member.name)
      .sort()
    expect(publishable).toEqual(PUBLISHED)

    const released = [...packages]
      .filter(([, config]) => config.release)
      .map(([name]) => name)
      .sort()
    expect(released).toEqual(PUBLISHED)

    for (const name of PUBLISHED) {
      expect(packages.get(name)?.versionGroup, name).toBe(GROUPS[name])
    }
  })

  it('opts every unpublished member out of publishing here too', () => {
    const unpublished = members.filter((member) => !member.publish)
    expect(unpublished.length).toBeGreaterThan(0)
    for (const { name } of unpublished) {
      expect(packages.get(name)?.publish, name).toBe(false)
    }
    for (const name of PUBLISHED) {
      expect(packages.get(name)?.publish, name).toBe(true)
    }
  })

  it('points the changelog at a file that exists', () => {
    const changelog = /^changelog_config\s*=\s*"([^"]+)"/m.exec(source)?.[1]
    expect(changelog).toBeTruthy()
    expect(existsSync(join(REPO_ROOT, changelog))).toBe(true)
  })

  it('is the configuration the release-crates job runs with', () => {
    const steps = readWorkflow(WORKFLOW)?.jobs?.['release-crates']?.steps ?? []
    const release = steps.find((step) =>
      String(step?.uses ?? '').startsWith('release-plz/action@'),
    )
    expect(release?.with).toMatchObject({
      command: 'release',
      manifest_path: 'Cargo.toml',
      config: CONFIG,
    })
  })
})
