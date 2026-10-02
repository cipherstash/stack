import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { parseSpecs, waitForVersions } from '../wait-for-npm-versions.mjs'
import { expr } from './lib/expressions.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The wait between the native publish jobs and `changeset publish`.
 *
 * Without it `changeset publish` asks npm about versions npm accepted a minute
 * earlier and does not list yet, publishes them a second time, and fails the
 * `release` job with E402 — which is what happened to protect-ffi 0.33.0 and
 * to @cipherstash/auth 0.44.1 on 2 October 2026.
 */

const SCRIPT = join(REPO_ROOT, 'scripts/wait-for-npm-versions.mjs')
const RELEASE = '.github/workflows/release.yml'

const FFI = [
  '@cipherstash/protect-ffi-darwin-arm64@0.33.0',
  '@cipherstash/protect-ffi-linux-x64-musl@0.33.0',
  '@cipherstash/protect-ffi@0.33.0',
].join(' ')
const AUTH = [
  '@cipherstash/auth-darwin-x64@0.44.1',
  '@cipherstash/auth-win32-x64-msvc@0.44.1',
  '@cipherstash/auth@0.44.1',
].join(' ')

/**
 * A registry whose package documents start listing a version after `hiddenFor`
 * lookups of that name, with a clock that only moves when the wait sleeps.
 */
function fakeRegistry(packages) {
  const calls = new Map()
  let clock = 0
  const sleeps = []
  return {
    calls,
    sleeps,
    now: () => clock,
    wait: async (ms) => {
      sleeps.push(ms)
      clock += ms
    },
    lookup: (name) => {
      calls.set(name, (calls.get(name) ?? 0) + 1)
      const entry = packages[name]
      if (entry === undefined) throw new Error(`unexpected lookup of ${name}`)
      if (entry instanceof Error) throw entry
      return calls.get(name) > (entry.hiddenFor ?? 0)
        ? entry.after
        : entry.before
    },
  }
}

const quiet = { log: () => {} }

describe('the published lists', () => {
  it('read as nothing for a skipped publish job, whose output is empty', () => {
    expect(parseSpecs('')).toEqual([])
    expect(parseSpecs(undefined)).toEqual([])
    expect(parseSpecs('  \n ')).toEqual([])
  })

  it('split each entry on its last `@`, so the scope survives', () => {
    expect(parseSpecs(`${AUTH}\n`)).toEqual([
      { name: '@cipherstash/auth-darwin-x64', version: '0.44.1' },
      { name: '@cipherstash/auth-win32-x64-msvc', version: '0.44.1' },
      { name: '@cipherstash/auth', version: '0.44.1' },
    ])
  })

  it('refuse an entry with no version rather than waiting for nothing', () => {
    expect(() => parseSpecs('@cipherstash/auth')).toThrow(/name@version/)
    expect(() => parseSpecs('@cipherstash/auth@')).toThrow(/name@version/)
  })
})

describe('the wait', () => {
  it('asks npm nothing when both publish jobs were skipped', async () => {
    const registry = fakeRegistry({})
    await waitForVersions([], { ...registry, ...quiet })
    expect(registry.calls.size).toBe(0)
    expect(registry.sleeps).toEqual([])
  })

  it('waits for the FFI and the auth packages, each until npm lists it', async () => {
    // The shape of both failures: some of the seven were listed in time and
    // some were not.
    const registry = fakeRegistry({
      '@cipherstash/protect-ffi-darwin-arm64': { after: ['0.32.0', '0.33.0'] },
      '@cipherstash/protect-ffi-linux-x64-musl': {
        before: ['0.32.0'],
        after: ['0.32.0', '0.33.0'],
        hiddenFor: 2,
      },
      '@cipherstash/protect-ffi': {
        before: ['0.32.0'],
        after: ['0.32.0', '0.33.0'],
        hiddenFor: 1,
      },
      '@cipherstash/auth-darwin-x64': {
        before: ['0.44.0'],
        after: ['0.44.0', '0.44.1'],
        hiddenFor: 3,
      },
      '@cipherstash/auth-win32-x64-msvc': { after: ['0.44.0', '0.44.1'] },
      '@cipherstash/auth': {
        before: ['0.44.0'],
        after: ['0.44.0', '0.44.1'],
        hiddenFor: 1,
      },
    })
    await waitForVersions([...parseSpecs(FFI), ...parseSpecs(AUTH)], {
      ...registry,
      ...quiet,
      intervalMs: 15_000,
    })
    // Three sleeps: the slowest package was hidden for three lookups.
    expect(registry.sleeps).toEqual([15_000, 15_000, 15_000])
    // A package is not asked about again once npm lists it.
    expect(Object.fromEntries(registry.calls)).toEqual({
      '@cipherstash/protect-ffi-darwin-arm64': 1,
      '@cipherstash/protect-ffi-linux-x64-musl': 3,
      '@cipherstash/protect-ffi': 2,
      '@cipherstash/auth-darwin-x64': 4,
      '@cipherstash/auth-win32-x64-msvc': 1,
      '@cipherstash/auth': 2,
    })
  })

  it('reads a 404 as not listed yet: a first publish of a new package', async () => {
    const registry = fakeRegistry({
      '@cipherstash/auth': { before: null, after: ['0.1.0'], hiddenFor: 2 },
    })
    await waitForVersions(parseSpecs('@cipherstash/auth@0.1.0'), {
      ...registry,
      ...quiet,
    })
    expect(registry.calls.get('@cipherstash/auth')).toBe(3)
  })

  it('is satisfied by the exact version only', async () => {
    const registry = fakeRegistry({
      '@cipherstash/auth': { after: ['0.44.10', '0.44.1-rc.0'] },
    })
    await expect(
      waitForVersions(parseSpecs('@cipherstash/auth@0.44.1'), {
        ...registry,
        ...quiet,
        timeoutMs: 30_000,
        intervalMs: 15_000,
      }),
    ).rejects.toThrow(/@cipherstash\/auth@0\.44\.1/)
  })

  it('times out naming every version npm never listed, and only those', async () => {
    const registry = fakeRegistry({
      '@cipherstash/auth': { after: ['0.44.1'] },
      '@cipherstash/auth-darwin-x64': { after: ['0.44.0'] },
    })
    const waiting = waitForVersions(
      parseSpecs(
        '@cipherstash/auth@0.44.1 @cipherstash/auth-darwin-x64@0.44.1',
      ),
      { ...registry, ...quiet, timeoutMs: 60_000, intervalMs: 15_000 },
    )
    await expect(waiting).rejects.toThrow(
      /within 60s: @cipherstash\/auth-darwin-x64@0\.44\.1\. /,
    )
    // It polled until the deadline, not once.
    expect(registry.calls.get('@cipherstash/auth-darwin-x64')).toBe(5)
  })

  it('retries a registry error until the deadline, then reports it', async () => {
    const registry = fakeRegistry({
      '@cipherstash/auth': new Error(
        'npm view @cipherstash/auth failed: ETIMEDOUT',
      ),
    })
    await expect(
      waitForVersions(parseSpecs('@cipherstash/auth@0.44.1'), {
        ...registry,
        ...quiet,
        timeoutMs: 30_000,
        intervalMs: 15_000,
      }),
    ).rejects.toThrow(/@cipherstash\/auth@0\.44\.1 \(npm view .* ETIMEDOUT\)/)
    expect(registry.calls.get('@cipherstash/auth')).toBe(3)
  })
})

/**
 * The script as the workflow runs it, against an `npm` shim on PATH that
 * answers `npm view <name> versions --json` and counts the calls.
 */
describe('the script', () => {
  let dir
  afterEach(() => dir && rmSync(dir, { recursive: true, force: true }))

  function run(env, packages) {
    dir = mkdtempSync(join(tmpdir(), 'wait-for-npm-'))
    const state = join(dir, 'state.json')
    writeFileSync(state, JSON.stringify({ packages, calls: {} }))
    writeFileSync(
      join(dir, 'npm'),
      '#!/usr/bin/env node\n' +
        "const fs = require('node:fs')\n" +
        "const state = JSON.parse(fs.readFileSync(process.env.FAKE_NPM_STATE, 'utf8'))\n" +
        'const [command, name] = process.argv.slice(2)\n' +
        "if (command !== 'view') process.exit(2)\n" +
        'state.calls[name] = (state.calls[name] ?? 0) + 1\n' +
        'fs.writeFileSync(process.env.FAKE_NPM_STATE, JSON.stringify(state))\n' +
        'const entry = state.packages[name]\n' +
        'const listed = entry && state.calls[name] > (entry.hiddenFor ?? 0) ? entry.after : null\n' +
        "if (!listed) { process.stderr.write('npm error code E404\\n'); process.exit(1) }\n" +
        'process.stdout.write(JSON.stringify(listed))\n',
    )
    chmodSync(join(dir, 'npm'), 0o755)
    const result = spawnSync('node', [SCRIPT], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${dir}${delimiter}${process.env.PATH}`,
        FAKE_NPM_STATE: state,
        FFI_PUBLISHED: '',
        AUTH_PUBLISHED: '',
        NPM_WAIT_INTERVAL_SECONDS: '0',
        ...env,
      },
    })
    const calls = JSON.parse(readFileSync(state, 'utf8')).calls
    return { ...result, calls }
  }

  it('returns at once when both publish jobs were skipped', () => {
    const { status, stdout, calls } = run({}, {})
    expect(status).toBe(0)
    expect(stdout).toContain('no wait')
    expect(calls).toEqual({})
  })

  it('waits for the auth packages when publish-ffi was skipped', () => {
    const { status, stdout, calls } = run(
      {
        AUTH_PUBLISHED:
          '@cipherstash/auth-darwin-x64@0.44.1 @cipherstash/auth@0.44.1',
      },
      {
        '@cipherstash/auth-darwin-x64': { after: ['0.44.1'], hiddenFor: 2 },
        '@cipherstash/auth': { after: ['0.44.1'] },
      },
    )
    expect(status).toBe(0)
    expect(stdout).toContain('npm lists all 2.')
    expect(calls).toEqual({
      '@cipherstash/auth-darwin-x64': 3,
      '@cipherstash/auth': 1,
    })
  })

  it('fails before `changeset publish` when npm never lists a version', () => {
    const { status, stderr } = run(
      {
        FFI_PUBLISHED: '@cipherstash/protect-ffi@0.33.0',
        NPM_WAIT_TIMEOUT_SECONDS: '0',
      },
      {},
    )
    expect(status).toBe(1)
    expect(stderr).toMatch(
      /::error::npm did not list these within 0s: @cipherstash\/protect-ffi@0\.33\.0\. /,
    )
  })
})

describe('release.yml waits for both native publish jobs', () => {
  const jobs = readWorkflow(RELEASE).jobs

  for (const name of ['publish-ffi', 'publish-auth']) {
    it(`${name} exports the list it published`, () => {
      const job = jobs[name]
      expect(job.outputs?.published).toBe(
        expr('steps.publish.outputs.published'),
      )
      const publish = job.steps.find((step) => step.id === 'publish')
      // Every tarball it handled, published now or before: the same list it
      // writes to published.txt for the tags.
      expect(publish.run).toContain(`echo "published=\${published[*]}"`)
      expect(publish.run).toContain('>> "$GITHUB_OUTPUT"')
    })
  }

  it('runs the wait in `release`, before `changeset publish`, on both lists', () => {
    const release = jobs.release
    expect(release.needs).toEqual(
      expect.arrayContaining(['publish-ffi', 'publish-auth']),
    )
    const steps = release.steps
    const wait = steps.findIndex((step) =>
      String(step.run ?? '').includes('scripts/wait-for-npm-versions.mjs'),
    )
    const publish = steps.findIndex((step) =>
      String(step.uses ?? '').startsWith('changesets/action'),
    )
    expect(
      wait,
      'no step runs scripts/wait-for-npm-versions.mjs',
    ).toBeGreaterThan(-1)
    expect(wait, 'the wait must come before changesets/action').toBeLessThan(
      publish,
    )
    expect(steps[wait].if, 'the wait must not be skippable').toBeUndefined()
    expect(steps[wait].env).toEqual({
      FFI_PUBLISHED: expr('needs.publish-ffi.outputs.published'),
      AUTH_PUBLISHED: expr('needs.publish-auth.outputs.published'),
    })
  })
})
