import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  lockstepPeers,
  withoutPeers,
  withPeersRestored,
} from '../with-lockstep-peers-hidden.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * `@cipherstash/auth` and its six platform packages version together as one
 * changesets `fixed` group, and the wrapper pins the six as exact-version
 * optional PEER dependencies (`workspace:*`). Changesets gives a dependent a
 * MAJOR bump when a peer leaves its range on a minor, and reads `workspace:*`
 * as "exactly the current version" — so a `minor` changeset on the wrapper
 * planned 0.44.1 -> 1.0.0 for all seven, with no changeset asking for a major.
 * It was caught in the Version Packages PR, by a person, days after the minor
 * changeset merged.
 *
 * `scripts/with-lockstep-peers-hidden.mjs` runs `changeset version` with those
 * peers hidden. Nothing type-checks a release plan, and the only other place
 * the number shows up is a generated PR diff, so this file drives the REAL
 * changesets CLI over a throwaway workspace shaped like the auth group: once
 * bare, to pin the behaviour the wrapper exists for, and once through the
 * wrapper.
 */

const WRAPPER = join(REPO_ROOT, 'scripts/with-lockstep-peers-hidden.mjs')
const CHANGESETS_CLI = createRequire(join(REPO_ROOT, 'package.json')).resolve(
  '@changesets/cli/bin.js',
)

const WRAPPER_PEERS = {
  'wrapper-darwin': 'workspace:*',
  'wrapper-linux': 'workspace:*',
  // A peer outside the fixed group. It must survive untouched.
  'some-framework': '>=1.132.0',
}

const dirs = []
afterEach(() => {
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true })
  }
})

/**
 * A workspace with a `wrapper` package and two platform packages in one fixed
 * group at 0.44.1, and one changeset bumping `wrapper` by `bump`.
 */
function workspace(bump = 'minor') {
  const dir = mkdtempSync(join(tmpdir(), 'lockstep-peers-'))
  dirs.push(dir)
  const write = (file, value) => {
    mkdirSync(join(dir, file, '..'), { recursive: true })
    writeFileSync(
      join(dir, file),
      typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`,
    )
  }
  write('package.json', {
    name: 'fixture',
    private: true,
    workspaces: ['packages/*'],
  })
  write('.changeset/config.json', {
    changelog: false,
    commit: false,
    fixed: [['wrapper', 'wrapper-darwin', 'wrapper-linux']],
    access: 'restricted',
    baseBranch: 'main',
    updateInternalDependencies: 'patch',
    // As in this repo's own config. It is what makes `workspace:*` count as
    // out of range rather than every peer bump being a major.
    ___experimentalUnsafeOptions_WILL_CHANGE_IN_PATCH: {
      onlyUpdatePeerDependentsWhenOutOfRange: true,
    },
  })
  write('.changeset/bump.md', `---\n'wrapper': ${bump}\n---\n\nA change.\n`)
  write('packages/wrapper/package.json', {
    name: 'wrapper',
    version: '0.44.1',
    peerDependencies: WRAPPER_PEERS,
    peerDependenciesMeta: {
      'wrapper-darwin': { optional: true },
      'wrapper-linux': { optional: true },
    },
    dependencies: { 'left-pad': '^1.0.0' },
  })
  for (const name of ['wrapper-darwin', 'wrapper-linux']) {
    write(`packages/${name}/package.json`, { name, version: '0.44.1' })
  }
  return dir
}

const manifest = (dir, name) =>
  JSON.parse(readFileSync(join(dir, 'packages', name, 'package.json'), 'utf8'))

const versions = (dir) =>
  Object.fromEntries(
    ['wrapper', 'wrapper-darwin', 'wrapper-linux'].map((name) => [
      name,
      manifest(dir, name).version,
    ]),
  )

/** Run `node <args>` in `dir`, returning its status and combined output. */
function run(dir, args) {
  const result = spawnSync(process.execPath, args, {
    cwd: dir,
    encoding: 'utf8',
  })
  return {
    status: result.status,
    output: `${result.stdout ?? ''}${result.stderr ?? ''}`,
  }
}

describe('changeset version over a fixed group with workspace:* peers', () => {
  it('bare, turns a minor changeset into a major for the whole group', () => {
    // The behaviour the wrapper exists for, pinned against the installed
    // changesets. If this ever fails because the group comes out at 0.45.0,
    // changesets has stopped applying its peer rule inside a fixed group, and
    // `with-lockstep-peers-hidden.mjs` can be retired.
    const dir = workspace('minor')
    const { status, output } = run(dir, [CHANGESETS_CLI, 'version'])
    expect(status, output).toBe(0)
    expect(versions(dir)).toEqual({
      wrapper: '1.0.0',
      'wrapper-darwin': '1.0.0',
      'wrapper-linux': '1.0.0',
    })
  })

  it('through the wrapper, gives the minor that was asked for', () => {
    const dir = workspace('minor')
    const before = manifest(dir, 'wrapper')
    const { status, output } = run(dir, [
      WRAPPER,
      process.execPath,
      CHANGESETS_CLI,
      'version',
    ])
    expect(status, output).toBe(0)
    expect(versions(dir)).toEqual({
      wrapper: '0.45.0',
      'wrapper-darwin': '0.45.0',
      'wrapper-linux': '0.45.0',
    })

    // The manifest that gets committed and packed is the one that was there,
    // with a new version and nothing else: same peers, same order, same
    // optional markers. A wrapper that left the peers out would publish a
    // package that no longer names the binaries it needs.
    const after = manifest(dir, 'wrapper')
    expect(after).toEqual({ ...before, version: '0.45.0' })
    expect(Object.keys(after)).toEqual(Object.keys(before))
    expect(Object.keys(after.peerDependencies)).toEqual(
      Object.keys(WRAPPER_PEERS),
    )
    expect(output).toMatch(
      /hiding 2 lockstep peer\(s\) of packages\/wrapper\/package\.json/,
    )
  })

  it('leaves a patch alone, which the peer rule never touched', () => {
    const dir = workspace('patch')
    const { status, output } = run(dir, [
      WRAPPER,
      process.execPath,
      CHANGESETS_CLI,
      'version',
    ])
    expect(status, output).toBe(0)
    expect(versions(dir).wrapper).toBe('0.44.2')
  })

  it('restores the peers and passes the exit status on when the command fails', () => {
    const dir = workspace('minor')
    const file = join(dir, 'packages/wrapper/package.json')
    const before = readFileSync(file, 'utf8')
    const { status } = run(dir, [
      WRAPPER,
      process.execPath,
      '-e',
      // Fail while the peers are hidden, having proved that they are.
      `const peers = require(${JSON.stringify(file)}).peerDependencies;
       if ('wrapper-darwin' in peers || !('some-framework' in peers)) process.exit(9);
       process.exit(3);`,
    ])
    expect(status).toBe(3)
    expect(readFileSync(file, 'utf8')).toBe(before)
  })

  it('refuses to run with no command', () => {
    const dir = workspace('minor')
    const { status, output } = run(dir, [WRAPPER])
    expect(status).toBe(2)
    expect(output).toMatch(/usage:/)
  })
})

describe('lockstepPeers', () => {
  const fixed = [['a', 'a-darwin', 'a-linux']]

  it('picks the workspace peers a package has on its own fixed group', () => {
    expect(
      lockstepPeers(
        {
          name: 'a',
          peerDependencies: {
            'a-darwin': 'workspace:*',
            'a-linux': 'workspace:^',
            react: '>=18',
          },
        },
        fixed,
      ),
    ).toEqual(['a-darwin', 'a-linux'])
  })

  it('leaves a peer between packages that do not version together', () => {
    // Here the changesets rule is right: `b` really can fall out of range.
    expect(
      lockstepPeers(
        { name: 'b', peerDependencies: { a: 'workspace:*' } },
        fixed,
      ),
    ).toEqual([])
    expect(
      lockstepPeers(
        { name: 'a', peerDependencies: { b: 'workspace:*' } },
        fixed,
      ),
    ).toEqual([])
  })

  it('leaves a group peer that is not a workspace range', () => {
    // A literal range is published as written, so it can go out of range.
    expect(
      lockstepPeers(
        { name: 'a', peerDependencies: { 'a-darwin': '0.44.1' } },
        fixed,
      ),
    ).toEqual([])
  })

  it('copes with a package that has no peers at all', () => {
    expect(lockstepPeers({ name: 'a-darwin' }, fixed)).toEqual([])
  })
})

describe('withoutPeers / withPeersRestored', () => {
  const original = `${JSON.stringify(
    {
      name: 'a',
      version: '0.44.1',
      peerDependencies: { 'a-darwin': 'workspace:*', react: '>=18' },
      dependencies: { x: '^1.0.0' },
    },
    null,
    '\t',
  )}\n`

  it('removes only the named peers, keeping the key and the formatting', () => {
    const hidden = withoutPeers(original, ['a-darwin'])
    expect(JSON.parse(hidden).peerDependencies).toEqual({ react: '>=18' })
    expect(hidden).toMatch(/^\t"name"/m)
    expect(hidden.endsWith('}\n')).toBe(true)
    // An emptied table stays as a key, so it keeps its place in the file.
    const emptied = JSON.parse(withoutPeers(original, ['a-darwin', 'react']))
    expect(Object.keys(emptied)).toEqual(Object.keys(JSON.parse(original)))
    expect(emptied.peerDependencies).toEqual({})
  })

  it('restores the named peers and keeps what the command wrote', () => {
    const afterCommand = JSON.stringify(
      {
        ...JSON.parse(withoutPeers(original, ['a-darwin'])),
        version: '0.45.0',
        // A range the command rewrote on a peer that was never hidden.
        peerDependencies: { react: '>=19' },
      },
      null,
      '\t',
    )
    const restored = JSON.parse(
      withPeersRestored(afterCommand, original, ['a-darwin']),
    )
    expect(restored.version).toBe('0.45.0')
    expect(restored.peerDependencies).toEqual({
      'a-darwin': 'workspace:*',
      react: '>=19',
    })
    expect(Object.keys(restored.peerDependencies)).toEqual([
      'a-darwin',
      'react',
    ])
  })
})

describe('this repository', () => {
  const read = (file) => JSON.parse(readFileSync(join(REPO_ROOT, file), 'utf8'))

  it('is the case the wrapper exists for: auth pins its six platform packages as lockstep peers', () => {
    // If this fails because the platform packages moved out of
    // `peerDependencies`, the wrapper has nothing left to hide here. Before
    // deleting it, read `scripts/with-lockstep-peers-hidden.mjs` for why they
    // are peers at all (Deno's resolver).
    const { fixed } = read('.changeset/config.json')
    const auth = read('languages/typescript/packages/auth/package.json')
    const hidden = lockstepPeers(auth, fixed)
    expect(hidden).toHaveLength(6)
    expect(hidden.every((name) => name.startsWith('@cipherstash/auth-'))).toBe(
      true,
    )
    // The peer on TanStack Start is not the group's own, and is not hidden.
    expect(auth.peerDependencies['@tanstack/react-start']).toBeTruthy()
    expect(hidden).not.toContain('@tanstack/react-start')
  })
})
