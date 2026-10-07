import { execFileSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  changelogSection,
  compareBuilds,
  DIRECT,
  dryRunPlan,
  eventually,
  GO_MANIFEST,
  GO_MODULE,
  GO_PACKAGE,
  GO_ROOT,
  GUESTS,
  goRelease,
  publish,
  releaseNotes,
  releaseTag,
  scratchBranch,
  sha256,
  UNRELEASED,
  verifyModuleVia,
  versionCommitVia,
} from '../golang-release.mjs'
import { buildGuests } from '../golang-release-build.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The Go module's release line (languages/golang/RELEASING.md).
 *
 * A Go module is fetched from the git tree at its tag, and the guests it
 * embeds are gitignored build outputs, so a release tags a commit made for it:
 * the commit that set the version plus the built guests. These hold the
 * decision (owed when the version has no tag), the checks before anything is
 * public, and the list of guests against the module that embeds them.
 */

const REF = '415b62cdb6f8d1c35b1b0cbc4b4a2e0f7c3d9a01'
const COMMIT = '9c0ffee5b6f8d1c35b1b0cbc4b4a2e0f7c3d9a02'
const REPO = 'cipherstash/stack'

const temps = []
function temp() {
  const dir = mkdtempSync(join(tmpdir(), 'golang-release-test-'))
  temps.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of temps.splice(0))
    rmSync(dir, { recursive: true, force: true })
})

/** A build directory holding `contents[path]` for every guest. */
function buildDir(contents = {}) {
  const dir = temp()
  for (const { path } of GUESTS) {
    const file = join(dir, path)
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, contents[path] ?? `guest ${path}`)
  }
  return dir
}

describe('whether a release is owed', () => {
  const asking = ({ tags = {}, ref = REF } = {}) => {
    const asked = []
    return {
      asked,
      tagCommit: (tag) => {
        asked.push(`tag ${tag}`)
        return tags[tag] ?? null
      },
      versionCommit: (version) => {
        asked.push(`commit ${version}`)
        return ref
      },
    }
  }

  it('is not, before the first Go changeset is versioned, and asks nothing', () => {
    const world = asking()
    const result = goRelease({ version: UNRELEASED, ...world })
    expect(result.needed).toBe(false)
    expect(result.reason).toContain(GO_PACKAGE)
    expect(world.asked).toEqual([])
  })

  it('is not when the version is tagged, and walks no history to say so', () => {
    const world = asking({ tags: { 'languages/golang/v0.1.0': COMMIT } })
    const result = goRelease({ version: '0.1.0', ...world })
    expect(result).toMatchObject({
      needed: false,
      tag: 'languages/golang/v0.1.0',
    })
    expect(world.asked).toEqual(['tag languages/golang/v0.1.0'])
  })

  it('is when the version has no tag, at the commit that set it', () => {
    const world = asking()
    expect(goRelease({ version: '0.2.0', ...world })).toMatchObject({
      needed: true,
      version: '0.2.0',
      tag: 'languages/golang/v0.2.0',
      prerelease: false,
      ref: REF,
    })
    expect(world.asked).toEqual(['tag languages/golang/v0.2.0', 'commit 0.2.0'])
  })

  it('marks a changesets prerelease as one', () => {
    expect(goRelease({ version: '0.2.0-beta.1', ...asking() }).prerelease).toBe(
      true,
    )
  })

  it.each(['v0.1.0', '0.1', '0.1.0; rm -rf /', ''])(
    'refuses the version %j',
    (version) => {
      expect(() => goRelease({ version, ...asking() })).toThrow(/not X\.Y\.Z/)
    },
  )

  it('is always owed in a dry run, at the dispatched commit, whatever the tags say', () => {
    expect(dryRunPlan({ version: UNRELEASED, head: REF })).toMatchObject({
      needed: true,
      version: UNRELEASED,
      ref: REF,
    })
    expect(() => dryRunPlan({ version: 'main', head: REF })).toThrow(
      /not X\.Y\.Z/,
    )
  })

  it('tags under the module path, as Go requires for a module in a subdirectory', () => {
    expect(releaseTag('1.2.3')).toBe(`${GO_ROOT}/v1.2.3`)
    expect(GO_MODULE.endsWith(`/${GO_ROOT}`)).toBe(true)
  })
})

describe('the commit that set the version', () => {
  function history(version) {
    const dir = temp()
    const git = (...args) =>
      execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim()
    git('init', '-q', '-b', 'main')
    git('config', 'user.email', 'test@example.com')
    git('config', 'user.name', 'test')
    git('config', 'commit.gpgsign', 'false')
    const write = (v) => {
      mkdirSync(join(dir, GO_ROOT), { recursive: true })
      writeFileSync(
        join(dir, GO_MANIFEST),
        `${JSON.stringify({ name: GO_PACKAGE, version: v, private: true }, null, 2)}\n`,
      )
    }
    write(UNRELEASED)
    git('add', '.')
    git('commit', '-q', '-m', 'placeholder')
    write(version)
    git('commit', '-q', '-am', 'version packages')
    const bump = git('rev-parse', 'HEAD')
    writeFileSync(join(dir, 'later.txt'), 'merged after the bump')
    git('add', '.')
    git('commit', '-q', '-m', 'later')
    return { git, bump }
  }

  it('is the last commit to change the version line, not the head', () => {
    const { git, bump } = history('0.1.0')
    expect(versionCommitVia(git)('0.1.0')).toBe(bump)
  })

  it('refuses a history that sets another version', () => {
    const { git } = history('0.1.0')
    expect(() => versionCommitVia(git)('0.2.0')).toThrow(
      /sets 0\.1\.0, not 0\.2\.0/,
    )
  })

  it('refuses a shallow checkout rather than guessing', () => {
    const shallow = (...args) =>
      args[0] === 'rev-parse' ? 'true' : 'unreachable'
    expect(() => versionCommitVia(shallow)('0.1.0')).toThrow(/fetch-depth: 0/)
  })
})

describe('the two builds', () => {
  it('pass when identical, carrying each guest with its hash', () => {
    const guests = compareBuilds(buildDir(), buildDir())
    expect(guests.map((g) => g.path)).toEqual(GUESTS.map((g) => g.path))
    for (const guest of guests) {
      expect(guest.sha256).toBe(sha256(guest.bytes))
    }
  })

  it('stop the release when one guest differs', () => {
    const [path] = GUESTS.map((g) => g.path)
    expect(() =>
      compareBuilds(buildDir(), buildDir({ [path]: 'a different build' })),
    ).toThrow(/two builds .* differ .* nothing was tagged/)
  })

  it('stop the release when a guest is missing', () => {
    const second = buildDir()
    rmSync(join(second, GUESTS[0].path))
    expect(() => compareBuilds(buildDir(), second)).toThrow(
      /missing from the build/,
    )
  })
})

describe('building the guests', () => {
  it('runs each task and collects what it wrote', () => {
    const root = temp()
    const out = temp()
    const ran = []
    const built = buildGuests({
      root,
      out,
      run: (task) => {
        ran.push(task)
        const { path } = GUESTS.find((g) => g.task === task)
        mkdirSync(dirname(join(root, path)), { recursive: true })
        writeFileSync(join(root, path), `built by ${task}`)
      },
    })
    expect(ran).toEqual(GUESTS.map((g) => g.task))
    for (const { path, sha256: hash } of built) {
      expect(readFileSync(join(out, path), 'utf8')).toMatch(/^built by /)
      expect(hash).toBe(sha256(readFileSync(join(out, path))))
    }
  })

  it('does not let a stale guest stand in for one the task did not write', () => {
    const root = temp()
    const [{ path }] = GUESTS
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), 'from an earlier build')
    expect(() => buildGuests({ root, out: temp(), run: () => {} })).toThrow(
      /finished without writing/,
    )
  })
})

describe('the release notes', () => {
  const changelog = [
    `# ${GO_PACKAGE}`,
    '',
    '## 0.2.0',
    '',
    '### Minor Changes',
    '',
    '- abc1234: Keysets resolve in one call.',
    '',
    '## 0.1.0',
    '',
    '### Minor Changes',
    '',
    '- def5678: The first release.',
    '',
  ].join('\n')

  it("take the version's own section of the changelog", () => {
    expect(changelogSection(changelog, '0.2.0')).toBe(
      '### Minor Changes\n\n- abc1234: Keysets resolve in one call.',
    )
    expect(changelogSection(changelog, '0.1.0')).toContain('The first release.')
  })

  it('refuse a version the changelog has no section for', () => {
    expect(() => changelogSection(changelog, '0.3.0')).toThrow(
      /no `## 0\.3\.0`/,
    )
  })

  it('say how to install the version and list every guest with its hash', () => {
    const guests = GUESTS.map(({ path }) => ({ path, sha256: sha256(path) }))
    const notes = releaseNotes({
      version: '0.2.0',
      section: 'S',
      ref: REF,
      guests,
    })
    expect(notes).toContain(`go get ${GO_MODULE}@v0.2.0`)
    expect(notes).toContain(REF)
    for (const { path, sha256: hash } of guests) {
      expect(notes).toContain(`| \`${path}\` | \`${hash}\` |`)
    }
  })
})

describe('publishing', () => {
  const guests = GUESTS.map(({ path }) => ({
    path,
    bytes: Buffer.from(`guest ${path}`),
    sha256: sha256(`guest ${path}`),
  }))

  function github({
    branchExists = false,
    failVerify = false,
    tagged = null,
  } = {}) {
    const calls = []
    return {
      calls,
      tagCommit: () => tagged,
      api: (method, path, body) => {
        calls.push([method, path, body])
        if (method === 'GET') {
          return branchExists
            ? [{ ref: `refs/heads/${scratchBranch('0.2.0')}` }]
            : []
        }
        return {}
      },
      graphql: (_query, variables) => {
        calls.push(['GRAPHQL', variables.input])
        return { createCommitOnBranch: { commit: { oid: COMMIT } } }
      },
      verify: (commit) => {
        calls.push(['VERIFY', commit])
        if (failVerify) throw new Error('the module has no guest')
      },
    }
  }

  const run = (world) =>
    publish({
      repo: REPO,
      version: '0.2.0',
      tag: releaseTag('0.2.0'),
      ref: REF,
      prerelease: false,
      guests,
      notes: 'notes',
      ...world,
    })

  it('makes the commit on a scratch branch, checks it, then tags and releases it', () => {
    const world = github()
    expect(run(world)).toBe(COMMIT)
    const steps = world.calls.map(([kind, path]) =>
      kind === 'GRAPHQL' || kind === 'VERIFY' ? kind : `${kind} ${path}`,
    )
    expect(steps).toEqual([
      `GET repos/${REPO}/git/matching-refs/heads/release-golang/v0.2.0`,
      `POST repos/${REPO}/git/refs`,
      'GRAPHQL',
      'VERIFY',
      `POST repos/${REPO}/git/refs`,
      `DELETE repos/${REPO}/git/refs/heads/release-golang/v0.2.0`,
      `POST repos/${REPO}/releases`,
    ])
    expect(world.calls[1][2]).toEqual({
      ref: 'refs/heads/release-golang/v0.2.0',
      sha: REF,
    })
    expect(world.calls[4][2]).toEqual({
      ref: 'refs/tags/languages/golang/v0.2.0',
      sha: COMMIT,
    })
    expect(world.calls[6][2]).toMatchObject({
      tag_name: 'languages/golang/v0.2.0',
      make_latest: 'false',
      prerelease: false,
    })
  })

  it('adds exactly the guests, on top of the commit that set the version', () => {
    const world = github()
    run(world)
    const [, input] = world.calls.find(([kind]) => kind === 'GRAPHQL')
    expect(input.expectedHeadOid).toBe(REF)
    expect(input.fileChanges.additions).toEqual(
      guests.map(({ path, bytes }) => ({
        path,
        contents: bytes.toString('base64'),
      })),
    )
    expect(input.fileChanges.deletions).toBeUndefined()
  })

  it('pushes no tag and writes no release when the check fails, and drops the branch', () => {
    const world = github({ failVerify: true })
    expect(() => run(world)).toThrow(/no guest/)
    const writes = world.calls
      .filter(([kind]) => kind === 'POST')
      .map(([, , body]) => body)
    expect(writes).toEqual([
      { ref: 'refs/heads/release-golang/v0.2.0', sha: REF },
    ])
    expect(world.calls.at(-1)).toEqual([
      'DELETE',
      `repos/${REPO}/git/refs/heads/release-golang/v0.2.0`,
      undefined,
    ])
  })

  it('resets a scratch branch a failed run left behind', () => {
    const world = github({ branchExists: true })
    run(world)
    expect(world.calls[1]).toEqual([
      'PATCH',
      `repos/${REPO}/git/refs/heads/release-golang/v0.2.0`,
      { sha: REF, force: true },
    ])
  })

  it('stops a dry run after the check: no tag, no release, its own scratch branch', () => {
    const world = github({ tagged: COMMIT })
    expect(run({ ...world, dryRun: true })).toBe(COMMIT)
    const steps = world.calls.map(([kind, path]) =>
      kind === 'GRAPHQL' || kind === 'VERIFY' ? kind : `${kind} ${path}`,
    )
    expect(steps).toEqual([
      `GET repos/${REPO}/git/matching-refs/heads/release-golang/dry-run/v0.2.0`,
      `POST repos/${REPO}/git/refs`,
      'GRAPHQL',
      'VERIFY',
      `DELETE repos/${REPO}/git/refs/heads/release-golang/dry-run/v0.2.0`,
    ])
  })

  it('changes nothing when the tag appeared after the plan', () => {
    const world = github({ tagged: COMMIT })
    expect(() => run(world)).toThrow(/appeared .* nothing was changed/)
    expect(world.calls).toEqual([])
  })
})

describe('checking the module the go command receives', () => {
  function moduleDir(contents = {}) {
    const dir = temp()
    for (const { path } of GUESTS) {
      const file = join(dir, path.slice(GO_ROOT.length + 1))
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, contents[path] ?? `guest ${path}`)
    }
    return dir
  }
  const guests = GUESTS.map(({ path }) => ({
    path,
    sha256: sha256(`guest ${path}`),
  }))

  it('downloads the module at the query from the source asked for', () => {
    const dir = moduleDir()
    const seen = []
    verifyModuleVia(DIRECT, (args, env) => {
      seen.push({ args, env })
      return JSON.stringify({ Dir: dir })
    })(COMMIT, guests)
    expect(seen).toEqual([
      {
        args: ['mod', 'download', '-json', `${GO_MODULE}@${COMMIT}`],
        env: DIRECT,
      },
    ])
  })

  it('refuses a module whose guest is not the one built', () => {
    const [{ path }] = GUESTS
    const dir = moduleDir({ [path]: 'something else' })
    expect(() =>
      verifyModuleVia(DIRECT, () => JSON.stringify({ Dir: dir }))(
        COMMIT,
        guests,
      ),
    ).toThrow(/carries .* not /)
  })

  it('refuses a module with no guest, which is what a tag on main would give', () => {
    const dir = temp()
    expect(() =>
      verifyModuleVia(DIRECT, () => JSON.stringify({ Dir: dir }))(
        COMMIT,
        guests,
      ),
    ).toThrow(/has no /)
  })

  it('reports the go command refusing the download', () => {
    expect(() =>
      verifyModuleVia(DIRECT, () =>
        JSON.stringify({ Error: 'unknown revision' }),
      )(COMMIT, guests),
    ).toThrow(/unknown revision/)
  })

  it('retries while the proxy catches up, and gives up loudly', () => {
    let calls = 0
    const waits = []
    expect(
      eventually(
        () => {
          calls++
          if (calls < 3) throw new Error('not yet')
          return 'served'
        },
        { attempts: 4, delay: 1, wait: (ms) => waits.push(ms) },
      ),
    ).toBe('served')
    expect(waits).toEqual([1, 1])
    expect(() =>
      eventually(
        () => {
          throw new Error('never')
        },
        { attempts: 2, delay: 1, wait: () => {} },
      ),
    ).toThrow('never')
  })
})

describe('the guests the module embeds', () => {
  const tracked = (pattern) =>
    execFileSync('git', ['ls-files', '--', pattern], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean)

  /** Every package directory that embeds a `wasm` directory, and the files it reads from it. */
  function embeds() {
    return tracked(`${GO_ROOT}/**/*.go`)
      .filter((file) => !file.endsWith('_test.go'))
      .map((file) => ({
        file,
        text: readFileSync(join(REPO_ROOT, file), 'utf8'),
      }))
      .filter(({ text }) => /^\/\/go:embed wasm$/m.test(text))
      .map(({ file, text }) => ({
        dir: `${dirname(file)}/wasm`,
        reads: [...text.matchAll(/"wasm\/([^"]+\.wasm)"/g)].map((m) => m[1]),
      }))
  }

  it('lists exactly the directories the module embeds, with the files it reads', () => {
    const found = embeds()
    expect(found.length).toBeGreaterThan(0)
    expect(found.map((e) => e.dir).sort()).toEqual(
      GUESTS.map(({ path }) => dirname(path)).sort(),
    )
    for (const { dir, reads } of found) {
      const listed = GUESTS.filter(({ path }) => dirname(path) === dir).map(
        ({ path }) => path.slice(dir.length + 1),
      )
      expect(reads, dir).toEqual(listed)
    }
  })

  it("names each guest's mise task, which copies the guest to that path", () => {
    const mise = readFileSync(join(REPO_ROOT, 'mise.toml'), 'utf8')
    for (const { task, path } of GUESTS) {
      const body = mise.split(`[tasks."${task}"]`)[1]?.split(/^\[tasks\./m)[0]
      expect(body, task).toBeDefined()
      const name = path.split('/').at(-1)
      expect(body, task).toMatch(
        new RegExp(`cp "\\$module" \\.\\./(\\S+/)?${name.replace('.', '\\.')}`),
      )
    }
  })

  it('never commits a built guest to main: only a release commit holds one', () => {
    for (const { path } of GUESTS) {
      expect(tracked(path), path).toEqual([])
      expect(
        execFileSync('git', ['check-ignore', '--no-index', path], {
          cwd: REPO_ROOT,
          encoding: 'utf8',
        }).trim(),
      ).toBe(path)
    }
  })
})

describe('the placeholder that carries the version', () => {
  const manifest = JSON.parse(
    readFileSync(join(REPO_ROOT, GO_MANIFEST), 'utf8'),
  )

  it('is private, so neither the gate nor changeset publish ever sends it to npm', () => {
    expect(manifest).toMatchObject({ name: GO_PACKAGE, private: true })
  })

  it('carries a version and nothing a package manager would act on', () => {
    expect(Object.keys(manifest).sort()).toEqual([
      'description',
      'name',
      'private',
      'version',
    ])
  })

  it('is a workspace member, so changesets can version it', () => {
    const workspace = readFileSync(
      join(REPO_ROOT, 'pnpm-workspace.yaml'),
      'utf8',
    )
    expect(workspace).toMatch(new RegExp(`^\\s+- ${GO_ROOT}$`, 'm'))
  })
})

describe('release-golang.yml', () => {
  const workflow = readWorkflow('.github/workflows/release-golang.yml')
  // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, compared as the workflow spells it.
  const PLANNED_REF = '${{ needs.plan.outputs.ref }}'
  const steps = (job) => workflow.jobs[job].steps
  const runs = (job) =>
    steps(job)
      .map((s) => s.run)
      .filter(Boolean)

  it('starts when the version moves on main, and on demand', () => {
    expect(workflow.on.push).toEqual({
      branches: ['main'],
      paths: [GO_MANIFEST],
    })
    expect(workflow.on.workflow_dispatch.inputs.dry_run).toMatchObject({
      type: 'boolean',
      default: false,
    })
  })

  it('hands the dry-run input to both steps that act on it', () => {
    for (const job of ['plan', 'publish']) {
      const [step] = steps(job).filter((s) =>
        s.run?.startsWith('node scripts/golang-release.mjs'),
      )
      // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, compared as the workflow spells it.
      expect(step.env.DRY_RUN, job).toBe('${{ inputs.dry_run }}')
    }
  })

  it('reads history in plan, where the commit that set the version is found', () => {
    expect(steps('plan')[0].with['fetch-depth']).toBe(0)
    expect(runs('plan')).toEqual(['node scripts/golang-release.mjs plan'])
  })

  it('builds twice, at the planned commit', () => {
    expect(workflow.jobs.build.strategy.matrix.build).toHaveLength(2)
    expect(steps('build')[0].with.ref).toBe(PLANNED_REF)
    expect(runs('build')).toEqual([
      'node scripts/golang-release-build.mjs dist/golang-guests',
    ])
  })

  it('publishes from both builds, at the planned commit', () => {
    expect(workflow.jobs.publish.needs).toEqual(['plan', 'build'])
    expect(steps('publish')[0].with.ref).toBe(PLANNED_REF)
    const downloads = steps('publish')
      .filter((s) => s.uses?.startsWith('actions/download-artifact@'))
      .map((s) => [s.with.name, s.with.path])
    expect(downloads).toEqual([
      ['golang-guests-first', 'dist/first'],
      ['golang-guests-second', 'dist/second'],
    ])
    expect(runs('publish')).toEqual([
      'node scripts/golang-release.mjs publish dist/first dist/second',
    ])
  })

  it('writes to the repository from publish alone', () => {
    expect(workflow.permissions).toEqual({ contents: 'read' })
    for (const [name, job] of Object.entries(workflow.jobs)) {
      expect(job.permissions ?? {}, name).toEqual(
        name === 'publish' ? { contents: 'write' } : {},
      )
    }
  })

  it('exists where the docs say it does', () => {
    expect(existsSync(join(REPO_ROOT, GO_ROOT, 'RELEASING.md'))).toBe(true)
  })
})
