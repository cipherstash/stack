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
import {
  assetTag,
  changesetsTag,
  EQL_MANIFEST,
  eqlAssets,
  parsePublished,
  tagCommitVia,
} from '../eql-release-assets.mjs'
import { expr, runsWhen } from './lib/expressions.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * Whether EQL still owes its GitHub assets, and the release.yml wiring that
 * acts on the answer.
 *
 * EQL 3.0.6 reached npm on 2 October 2026 in a run whose `changeset publish`
 * then failed, and the step that would have reported the publish never ran.
 * No `eql-3.0.6` tag, release or image was built, and no later run would have
 * built them. These hold the replacement: an answer from npm and the tags,
 * and EQL jobs that still run when the `release` job fails.
 */

const SCRIPT = join(REPO_ROOT, 'scripts/eql-release-assets.mjs')
const RELEASE = '.github/workflows/release.yml'
const EQL = '@cipherstash/eql'
const TREE_VERSION = JSON.parse(
  readFileSync(join(REPO_ROOT, EQL_MANIFEST), 'utf8'),
).version

const HEAD = 'cb58a7b993646173578e2bb3c35d8e22ed1a7944'
const PUBLISHED_AT = '23e9af3f8e28c6d0495fdafcff096f58cbf0f4f7'

/** Lookups that record what they were asked. */
function world({ npm = [], tags = {} } = {}) {
  const asked = []
  return {
    asked,
    npmHas: (version) => {
      asked.push(`npm ${version}`)
      return npm.includes(version)
    },
    tagCommit: (tag) => {
      asked.push(`tag ${tag}`)
      return tags[tag] ?? null
    },
  }
}

const decide = (overrides, lookups) =>
  eqlAssets({
    version: '3.0.6',
    published: [],
    headSha: HEAD,
    ...lookups,
    ...overrides,
  })

describe('the decision', () => {
  it('owes the assets of a version on npm with no eql-<version> tag, at the commit that published it', () => {
    // EQL 3.0.6 today: published by an earlier run, never tagged.
    const result = decide(
      {},
      world({
        npm: ['3.0.5', '3.0.6'],
        tags: { '@cipherstash/eql@3.0.6': PUBLISHED_AT },
      }),
    )
    expect(result).toMatchObject({
      needed: true,
      version: '3.0.6',
      prerelease: false,
      ref: PUBLISHED_AT,
    })
  })

  it("counts this run's publish before npm lists it", () => {
    // A `changeset publish` that published EQL and then failed: the action
    // still reports EQL in `publishedPackages`.
    const lookups = world({ tags: { '@cipherstash/eql@3.0.6': HEAD } })
    const result = decide(
      {
        published: [
          { name: '@cipherstash/stack', version: '1.2.0' },
          { name: EQL, version: '3.0.6' },
        ],
      },
      lookups,
    )
    expect(result).toMatchObject({ needed: true, ref: HEAD })
    expect(lookups.asked).not.toContain('npm 3.0.6')
  })

  it("builds at this run's commit when this run published and pushed no tag", () => {
    const result = decide(
      { published: [{ name: EQL, version: '3.0.6' }] },
      world(),
    )
    expect(result).toMatchObject({ needed: true, ref: HEAD })
  })

  it('owes nothing once the eql-<version> tag exists, and asks npm nothing', () => {
    const lookups = world({
      npm: ['3.0.6'],
      tags: { 'eql-3.0.6': PUBLISHED_AT },
    })
    const result = decide(
      { published: [{ name: EQL, version: '3.0.6' }] },
      lookups,
    )
    expect(result).toMatchObject({ needed: false, ref: '' })
    expect(result.reason).toContain('eql-3.0.6 already exists')
    expect(lookups.asked).toEqual(['tag eql-3.0.6'])
  })

  it('owes nothing for a version that is not on npm', () => {
    // The tree's version did not publish: there is nothing to attach to.
    const result = decide({}, world({ npm: ['3.0.5'] }))
    expect(result).toMatchObject({ needed: false })
    expect(result.reason).toContain('is not on npm')
  })

  it('does not count another package, or another EQL version, as this run publishing EQL', () => {
    const result = decide(
      {
        published: [
          { name: '@cipherstash/eql-bindings', version: '3.0.6' },
          { name: EQL, version: '3.0.5' },
        ],
      },
      world(),
    )
    expect(result.needed).toBe(false)
  })

  it('refuses a version on npm when nothing says which commit published it', () => {
    expect(() => decide({}, world({ npm: ['3.0.6'] }))).toThrow(
      /no @cipherstash\/eql@3\.0\.6 tag says which commit published it/,
    )
  })

  it('marks a prerelease, so eql-image keeps the floating tags where they are', () => {
    const result = decide(
      {
        version: '3.1.0-rc.1',
        published: [{ name: EQL, version: '3.1.0-rc.1' }],
      },
      world(),
    )
    expect(result).toMatchObject({ needed: true, prerelease: true })
  })

  it('refuses a version that is not one, since it becomes a tag and a dispatch input', () => {
    expect(() => decide({ version: '3.0.6; rm -rf /' }, world())).toThrow(
      /not X\.Y\.Z/,
    )
  })

  it('owes nothing, and asks nothing, while EQL is a frozen publisher', () => {
    const lookups = world({ npm: ['3.0.6'] })
    const result = decide({ armed: false }, lookups)
    expect(result).toMatchObject({ needed: false })
    expect(result.reason).toContain('not armed')
    expect(lookups.asked).toEqual([])
  })

  it('names the tags it reads', () => {
    expect(assetTag('3.0.6')).toBe('eql-3.0.6')
    expect(changesetsTag('3.0.6')).toBe('@cipherstash/eql@3.0.6')
  })
})

describe('the inputs', () => {
  it('reads an empty publishedPackages as nothing published', () => {
    // changesets/action sets no output when it published nothing, and the
    // release job may not have run at all.
    expect(parsePublished('')).toEqual([])
    expect(parsePublished(undefined)).toEqual([])
    expect(parsePublished('[{"name":"a","version":"1.0.0"}]')).toEqual([
      { name: 'a', version: '1.0.0' },
    ])
  })

  it('refuses a publishedPackages it cannot read', () => {
    expect(() => parsePublished('{')).toThrow()
    expect(() => parsePublished('{"name":"a"}')).toThrow(/not an array/)
  })

  it('matches the tag exactly, not by prefix', () => {
    const call = () => [
      { ref: 'refs/tags/eql-3.0.60', object: { type: 'commit', sha: 'wrong' } },
    ]
    expect(tagCommitVia('o/r', call)('eql-3.0.6')).toBeNull()
  })

  it('follows an annotated tag to its commit', () => {
    const answers = {
      'repos/o/r/git/matching-refs/tags/eql-3.0.6': [
        { ref: 'refs/tags/eql-3.0.6', object: { type: 'tag', sha: 'tagobj' } },
      ],
      'repos/o/r/git/tags/tagobj': {
        object: { type: 'commit', sha: PUBLISHED_AT },
      },
    }
    expect(tagCommitVia('o/r', (path) => answers[path])('eql-3.0.6')).toBe(
      PUBLISHED_AT,
    )
  })

  it('lets a failed tag lookup throw rather than read as "no tag"', () => {
    const call = () => {
      throw new Error('HTTP 401')
    }
    expect(() => tagCommitVia('o/r', call)('eql-3.0.6')).toThrow('HTTP 401')
  })
})

/**
 * The script as the workflow runs it, over the real tree's version, with `npm`
 * and `gh` shimmed on PATH.
 */
describe('the script', () => {
  let dir
  afterEach(() => dir && rmSync(dir, { recursive: true, force: true }))

  function shim(name, body) {
    writeFileSync(join(dir, name), `#!/usr/bin/env node\n${body}`)
    chmodSync(join(dir, name), 0o755)
  }

  function run({ npm = null, api = {}, published = '' }) {
    dir = mkdtempSync(join(tmpdir(), 'eql-assets-'))
    const output = join(dir, 'output')
    writeFileSync(output, '')
    writeFileSync(join(dir, 'npm.json'), JSON.stringify(npm))
    writeFileSync(join(dir, 'api.json'), JSON.stringify(api))
    shim(
      'npm',
      "const versions = require(process.env.FAKE_DIR + '/npm.json')\n" +
        "if (versions === null) { process.stderr.write('npm error code E404\\n'); process.exit(1) }\n" +
        'process.stdout.write(JSON.stringify(versions))\n',
    )
    shim(
      'gh',
      "const api = require(process.env.FAKE_DIR + '/api.json')\n" +
        'const path = process.argv[3]\n' +
        "if (api[path] === 'fail') { process.stderr.write('HTTP 502\\n'); process.exit(1) }\n" +
        "process.stdout.write(JSON.stringify(api[path] ?? (path.includes('/matching-refs/') ? [] : null)))\n",
    )
    const result = spawnSync('node', [SCRIPT], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${dir}${delimiter}${process.env.PATH}`,
        FAKE_DIR: dir,
        GITHUB_OUTPUT: output,
        GITHUB_SHA: HEAD,
        REPO: 'cipherstash/stack',
        PUBLISHED_PACKAGES: published,
      },
    })
    return { ...result, output: readFileSync(output, 'utf8') }
  }

  const refs = (tag, sha) => ({
    [`repos/cipherstash/stack/git/matching-refs/tags/${tag}`]: [
      { ref: `refs/tags/${tag}`, object: { type: 'commit', sha } },
    ],
  })

  it('owes the assets of an already-published version with no tag', () => {
    const { status, stdout, output } = run({
      npm: [TREE_VERSION],
      api: refs(changesetsTag(TREE_VERSION), PUBLISHED_AT),
    })
    expect(status).toBe(0)
    expect(stdout).toContain(`building at ${PUBLISHED_AT}`)
    expect(output).toBe(
      `needed=true\nversion=${TREE_VERSION}\n` +
        `prerelease=${TREE_VERSION.includes('-')}\nref=${PUBLISHED_AT}\n`,
    )
  })

  it('owes them after a failed `changeset publish` that published EQL, before npm lists it', () => {
    const { status, output } = run({
      npm: null,
      published: JSON.stringify([{ name: EQL, version: TREE_VERSION }]),
    })
    expect(status).toBe(0)
    expect(output).toContain('needed=true\n')
    expect(output).toContain(`ref=${HEAD}\n`)
  })

  it('owes nothing once the tag exists', () => {
    const { status, output } = run({
      npm: [TREE_VERSION],
      api: refs(assetTag(TREE_VERSION), PUBLISHED_AT),
    })
    expect(status).toBe(0)
    expect(output).toContain('needed=false\n')
  })

  it('fails, writing nothing, when it cannot read the tags', () => {
    const { status, stderr, output } = run({
      npm: [TREE_VERSION],
      api: {
        [`repos/cipherstash/stack/git/matching-refs/tags/${assetTag(TREE_VERSION)}`]:
          'fail',
      },
    })
    expect(status).toBe(1)
    expect(stderr).toContain('::error::')
    expect(output).toBe('')
  })
})

// ---------------------------------------------------------------------------
// The release job graph
// ---------------------------------------------------------------------------

const STATUS_FUNCTION = /\b(always|cancelled|success|failure)\s*\(/

/**
 * Which jobs of release.yml run, for given job results and outputs, in a run
 * somebody cancelled while `cancelledDuring` was running, if it is set.
 *
 * A condition with no status function is ANDed with `success()`, and GitHub
 * evaluates that over every job up the `needs:` chain, not only the direct
 * ones: a skipped or failed ancestor anywhere skips the job
 * (https://github.com/actions/runner/issues/2205). That rule is the one that
 * matters here, because `publish-ffi` and `publish-auth` are skipped in most
 * runs.
 */
function simulate({ results = {}, outputs = {}, cancelledDuring } = {}) {
  const jobs = readWorkflow(RELEASE).jobs
  const needsOf = (name) => [jobs[name].needs ?? []].flat()
  const ancestors = (name, seen = new Set()) => {
    for (const parent of needsOf(name)) {
      if (!seen.has(parent)) {
        seen.add(parent)
        ancestors(parent, seen)
      }
    }
    return seen
  }

  const state = {}
  const pending = new Set(Object.keys(jobs))
  while (pending.size > 0) {
    const ready = [...pending].filter((name) =>
      needsOf(name).every((parent) => parent in state),
    )
    if (ready.length === 0) throw new Error('release.yml has a needs cycle')
    for (const name of ready) {
      pending.delete(name)
      if (name === cancelledDuring) {
        state[name] = { result: 'cancelled', outputs: outputs[name] ?? {} }
        continue
      }
      // Jobs that had already finished are unaffected by the cancel.
      const cancelled = ancestors(name).has(cancelledDuring)
      const condition = jobs[name].if === undefined ? '' : String(jobs[name].if)
      const context = {
        github: { event_name: 'push', ref: 'refs/heads/main' },
        vars: {},
        needs: Object.fromEntries(needsOf(name).map((n) => [n, state[n]])),
      }
      const runs = STATUS_FUNCTION.test(condition)
        ? runsWhen(condition, context, { cancelled })
        : !cancelled &&
          [...ancestors(name)].every((a) => state[a].result === 'success') &&
          (condition === '' || runsWhen(condition, context))
      state[name] = runs
        ? { result: results[name] ?? 'success', outputs: outputs[name] ?? {} }
        : { result: 'skipped', outputs: {} }
    }
  }
  return state
}

const OWED = {
  needed: 'true',
  version: '3.0.6',
  prerelease: 'false',
  ref: PUBLISHED_AT,
}

/** A production push where the gate found the given lines unpublished. */
function scenario({
  ffi = false,
  auth = false,
  results,
  eql = OWED,
  cancelledDuring,
  published = '',
}) {
  return simulate({
    cancelledDuring,
    results,
    outputs: {
      classify: { mode: 'production', version: '' },
      'eql-armed': { armed: 'true' },
      gate: { ffi: String(ffi), auth: String(auth) },
      release: { published_packages: published },
      'eql-assets': eql,
    },
  })
}

const EQL_JOBS = ['eql-assets', 'eql-sql', 'eql-docs', 'eql-image']
const ran = (state, names) =>
  Object.fromEntries(
    names.map((name) => [name, state[name].result !== 'skipped']),
  )

describe('release.yml builds the EQL assets whatever happened to `release`', () => {
  it('runs them on a release with no FFI or auth in it', () => {
    // publish-ffi and publish-auth are skipped, so under the implicit
    // `success()` every EQL job would be skipped with them.
    const state = scenario({})
    expect(state['publish-ffi'].result).toBe('skipped')
    expect(state['publish-auth'].result).toBe('skipped')
    expect(state.release.result).toBe('success')
    expect(ran(state, EQL_JOBS)).toEqual({
      'eql-assets': true,
      'eql-sql': true,
      'eql-docs': true,
      'eql-image': true,
    })
  })

  it('runs them when `changeset publish` fails', () => {
    // The 3.0.6 run: FFI published, then `changeset publish` failed with E402.
    const state = scenario({
      ffi: true,
      results: { release: 'failure' },
      published: JSON.stringify([{ name: EQL, version: '3.0.6' }]),
    })
    expect(state['publish-ffi'].result).toBe('success')
    expect(state.release.result).toBe('failure')
    expect(ran(state, EQL_JOBS)).toEqual({
      'eql-assets': true,
      'eql-sql': true,
      'eql-docs': true,
      'eql-image': true,
    })
  })

  it('still repairs an older release when a native build fails and skips `release`', () => {
    const state = scenario({
      auth: true,
      results: { 'auth-artifacts': 'failure' },
    })
    expect(state.release.result).toBe('skipped')
    expect(ran(state, EQL_JOBS)['eql-sql']).toBe(true)
  })

  it('builds nothing when nothing is owed', () => {
    const state = scenario({ eql: { ...OWED, needed: 'false', ref: '' } })
    expect(ran(state, EQL_JOBS)).toEqual({
      'eql-assets': true,
      'eql-sql': false,
      'eql-docs': false,
      'eql-image': false,
    })
  })

  it('builds the SQL and docs of a prerelease, and leaves the image alone', () => {
    const state = scenario({
      eql: { ...OWED, version: '3.1.0-rc.1', prerelease: 'true' },
    })
    expect(ran(state, EQL_JOBS)).toEqual({
      'eql-assets': true,
      'eql-sql': true,
      'eql-docs': true,
      'eql-image': false,
    })
  })

  it('stops at the first EQL job that fails', () => {
    const state = scenario({ results: { 'eql-sql': 'failure' } })
    expect(ran(state, ['eql-docs', 'eql-image'])).toEqual({
      'eql-docs': false,
      'eql-image': false,
    })
  })

  it('does nothing EQL when the gate fails', () => {
    const state = scenario({ results: { gate: 'failure' } })
    expect(ran(state, EQL_JOBS)).toEqual({
      'eql-assets': false,
      'eql-sql': false,
      'eql-docs': false,
      'eql-image': false,
    })
  })

  it('does nothing EQL in a run cancelled during `release`', () => {
    const state = scenario({ cancelledDuring: 'release' })
    expect(state.gate.result).toBe('success')
    expect(ran(state, EQL_JOBS)).toEqual({
      'eql-assets': false,
      'eql-sql': false,
      'eql-docs': false,
      'eql-image': false,
    })
  })
})

describe('release.yml feeds the decision and acts on it', () => {
  const jobs = readWorkflow(RELEASE).jobs

  it("hands `eql-assets` this run's publishedPackages straight from the step", () => {
    // A job output is evaluated when the job ends, failed or not; a step in
    // between would be skipped by the failure it exists to survive.
    expect(jobs.release.outputs).toEqual({
      published_packages: expr('steps.changesets.outputs.publishedPackages'),
    })
    const step = jobs['eql-assets'].steps.find((s) =>
      String(s.run ?? '').includes('scripts/eql-release-assets.mjs'),
    )
    expect(step?.env?.PUBLISHED_PACKAGES).toBe(
      expr('needs.release.outputs.published_packages'),
    )
    expect(jobs['eql-assets'].outputs).toEqual(
      Object.fromEntries(
        ['needed', 'version', 'prerelease', 'ref'].map((key) => [
          key,
          expr(`steps.${step.id}.outputs.${key}`),
        ]),
      ),
    )
  })

  it('builds the version, at the commit, that `eql-assets` names', () => {
    expect(jobs['eql-sql'].with).toMatchObject({
      ref: expr('needs.eql-assets.outputs.ref'),
      target_commitish: expr('needs.eql-assets.outputs.ref'),
      tag: `eql-${expr('needs.eql-assets.outputs.version')}`,
      prerelease: expr("needs.eql-assets.outputs.prerelease == 'true'"),
    })
    expect(jobs['eql-docs'].with).toEqual({
      ref: expr('needs.eql-assets.outputs.ref'),
      tag: `eql-${expr('needs.eql-assets.outputs.version')}`,
    })
    expect(jobs['eql-image'].steps[0].env.VERSION).toBe(
      expr('needs.eql-assets.outputs.version'),
    )
  })

  it('reads none of the outputs `release` no longer has', () => {
    const text = readFileSync(join(REPO_ROOT, RELEASE), 'utf8')
    expect(text).not.toMatch(/needs\.release\.outputs\.eql_/)
  })
})
