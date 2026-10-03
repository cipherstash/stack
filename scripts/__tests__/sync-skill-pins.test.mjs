import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { RELEASE_TRAIN_MANIFESTS } from '../../languages/typescript/packages/cli/src/release-train.ts'
import {
  releaseTrain,
  stableVersion,
  syncPins,
  syncSkillPins,
  trainVersions,
} from '../sync-skill-pins.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The version step moves the skill pins, so a Version Packages PR cannot leave
 * them behind. #1020 did, because no CI ran on it, and `main` then failed
 * `release-train.test.ts` until #1029 moved them by hand.
 */

const CONFIG = JSON.parse(
  readFileSync(join(REPO_ROOT, '.changeset/config.json'), 'utf8'),
)
const VERSIONS = new Map([
  ['stash', '1.2.1'],
  ['@cipherstash/stack', '1.2.1'],
])

describe('the release train', () => {
  it('is the fixed group that holds stash, and the CLI release train', () => {
    // Two lists of one set: changesets moves these together, and
    // release-train.test.ts checks their pins.
    expect(releaseTrain(CONFIG).sort()).toEqual(
      Object.keys(RELEASE_TRAIN_MANIFESTS).sort(),
    )
  })

  it('refuses a config with no group holding stash', () => {
    expect(() => releaseTrain({ fixed: [['@cipherstash/auth']] })).toThrow(
      /holds `stash`/,
    )
  })

  it('reads each version from the manifest the CLI embeds', () => {
    const versions = trainVersions(REPO_ROOT, releaseTrain(CONFIG))
    for (const [name, rel] of Object.entries(RELEASE_TRAIN_MANIFESTS)) {
      const manifest = JSON.parse(
        readFileSync(
          join(REPO_ROOT, 'languages/typescript/packages/cli', rel),
          'utf8',
        ),
      )
      expect(versions.get(name), name).toBe(manifest.version)
    }
  })

  it('refuses a train package with no manifest', () => {
    expect(() =>
      trainVersions(REPO_ROOT, ['stash', '@cipherstash/no-such-package']),
    ).toThrow(/@cipherstash\/no-such-package/)
  })
})

describe('the pins', () => {
  it('move the three forms the skills use', () => {
    const before = [
      "npx --package=stash@1.2.0 stash eql install --database-url 'postgres://...'",
      "} from 'npm:@cipherstash/stack@1.2.0/wasm-inline'",
      '"@cipherstash/stack/wasm-inline": "npm:@cipherstash/stack@1.2.0/wasm-inline"',
    ].join('\n')
    const { text, changes } = syncPins(before, VERSIONS)
    expect(text).toBe(
      [
        "npx --package=stash@1.2.1 stash eql install --database-url 'postgres://...'",
        "} from 'npm:@cipherstash/stack@1.2.1/wasm-inline'",
        '"@cipherstash/stack/wasm-inline": "npm:@cipherstash/stack@1.2.1/wasm-inline"',
      ].join('\n'),
    )
    expect(changes).toHaveLength(3)
  })

  it('pin the stable version during a prerelease', () => {
    expect(stableVersion('1.3.0-rc.0')).toBe('1.3.0')
    const { text } = syncPins(
      'npx --package=stash@1.2.1 stash',
      new Map([['stash', '1.3.0-rc.0']]),
    )
    expect(text).toBe('npx --package=stash@1.3.0 stash')
  })

  it('leave everything that is not a release-train pin alone', () => {
    const text = [
      '@cipherstash/eql@3.0.6',
      '@cipherstash/protect-ffi@0.33.0',
      '"stash": "^1.0.0"',
      'cipherstash@1.0.0',
      'mystash@1.0.0',
      'stash@latest',
    ].join('\n')
    expect(syncPins(text, VERSIONS)).toEqual({ text, changes: [] })
  })

  it('change nothing that is already current', () => {
    const text = 'npx --package=stash@1.2.1 stash eql install'
    expect(syncPins(text, VERSIONS)).toEqual({ text, changes: [] })
  })

  it('in this tree already name the release-train versions', () => {
    // What the next Version Packages PR starts from. A failure here names the
    // file: run `node scripts/sync-skill-pins.mjs`.
    expect(syncSkillPins({ root: REPO_ROOT, write: false })).toEqual([])
  })
})

/** The real script over a throwaway tree with one stale skill. */
describe('the script', () => {
  let root
  afterEach(() => root && rmSync(root, { recursive: true, force: true }))

  function fixture() {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'skill-pins-')))
    const write = (rel, text) => {
      mkdirSync(dirname(join(root, rel)), { recursive: true })
      writeFileSync(join(root, rel), text)
    }
    write(
      '.changeset/config.json',
      JSON.stringify({ fixed: [['stash', '@cipherstash/stack']] }),
    )
    write(
      'languages/typescript/packages/cli/package.json',
      JSON.stringify({ name: 'stash', version: '9.9.9' }),
    )
    write(
      'languages/typescript/packages/stack/package.json',
      JSON.stringify({ name: '@cipherstash/stack', version: '9.9.9' }),
    )
    write(
      'skills/stash-cli/SKILL.md',
      'npx --package=stash@9.9.8 stash eql install\n',
    )
    write('skills/other/SKILL.md', 'nothing pinned here\n')
    mkdirSync(join(root, 'scripts'))
    copyFileSync(
      join(REPO_ROOT, 'scripts/sync-skill-pins.mjs'),
      join(root, 'scripts/sync-skill-pins.mjs'),
    )
    return () =>
      spawnSync(process.execPath, [join(root, 'scripts/sync-skill-pins.mjs')], {
        cwd: root,
        encoding: 'utf8',
      })
  }

  it('moves a stale pin, and a second run changes nothing', () => {
    const run = fixture()
    const first = run()
    expect(first.status).toBe(0)
    expect(first.stdout).toContain(
      'skills/stash-cli/SKILL.md: stash@9.9.8 -> stash@9.9.9',
    )
    expect(readFileSync(join(root, 'skills/stash-cli/SKILL.md'), 'utf8')).toBe(
      'npx --package=stash@9.9.9 stash eql install\n',
    )

    const second = run()
    expect(second.status).toBe(0)
    expect(second.stdout).toContain('already name the release-train versions')
  })
})

describe('the root version script moves the pins', () => {
  const version = JSON.parse(
    readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'),
  ).scripts.version

  it('runs the pin sync after `changeset version`, which sets the versions', () => {
    expect(version).toContain('node scripts/sync-skill-pins.mjs')
    expect(version.indexOf('changeset version')).toBeLessThan(
      version.indexOf('sync-skill-pins.mjs'),
    )
    // `&&`, so a failed sync stops the release rather than shipping stale pins.
    expect(version).toMatch(
      /changeset version && .*node scripts\/sync-skill-pins\.mjs &&/,
    )
  })
})
