import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `release-golang.yml`'s `publish` job holds `contents: write` and builds the
 * release commit from an artifact made by `build`, the job that runs
 * third-party code (cargo build scripts, proc macros, the Go tests) AFTER it
 * writes `guests.sha256`. So the manifest is untrusted input to `publish`. If
 * `publish` took its paths from the manifest, a build-time compromise could
 * add a line for, say, `languages/golang/encrypt/init.go` and ship it on the
 * tag; the tree comparison would pass, because `build` derived the tree it
 * reports from the same manifest.
 *
 * These tests run the real "Commit the guests" step against forged artifacts.
 */

const WORKFLOW = readWorkflow('.github/workflows/release-golang.yml')
const GUESTS = String(WORKFLOW.env.GUESTS).split(/\s+/).filter(Boolean)
const COMMIT_STEP = WORKFLOW.jobs.publish.steps.find(
  (step) => step.name === 'Commit the guests',
)

const git = (cwd, ...args) =>
  execFileSync('git', args, { cwd, encoding: 'utf8' }).trim()

/**
 * The step runs on Linux under bash 5 with GNU coreutils. Two of those are not
 * a given on a developer's machine:
 *
 * - `mapfile` is bash 4 and later. macOS's own /bin/bash is 3.2, so the suite
 *   is skipped when the `bash` on PATH has no `mapfile`; every case needs it.
 * - `install -D` and `sha256sum -c` are GNU's. macOS's `install` has no `-D`.
 *   Homebrew coreutils provides GNU's as `ginstall` and `gsha256sum`, and the
 *   step sees them under their own names through a shim directory. Only the
 *   commit case reaches either; it is skipped without them. The refusal cases
 *   stop before both.
 *
 * Fixture hashes come from node:crypto, so writing a manifest needs neither.
 */
const BASH_HAS_MAPFILE =
  spawnSync('bash', ['-c', 'mapfile -t lines < /dev/null']).status === 0

const SHIMS = mkdtempSync(join(tmpdir(), 'go-release-artifact-bin-'))

/** Put GNU's `tool` on the shim PATH. False when there is none. */
function shimGnu(tool) {
  for (const name of [tool, `g${tool}`]) {
    const probe = spawnSync(name, ['--version'], { encoding: 'utf8' })
    if (probe.status !== 0 || !probe.stdout.includes('GNU coreutils')) continue
    if (name !== tool) {
      const path = execFileSync('bash', ['-c', `command -v ${name}`], {
        encoding: 'utf8',
      }).trim()
      symlinkSync(path, join(SHIMS, tool))
    }
    return true
  }
  return false
}
const GNU_COREUTILS = [shimGnu('install'), shimGnu('sha256sum')].every(Boolean)

afterAll(() => {
  rmSync(SHIMS, { recursive: true, force: true })
})

/** A `sha256sum` line: the hex digest, two spaces, the path. */
const sha256Line = (file, path) =>
  `${createHash('sha256').update(readFileSync(file)).digest('hex')}  ${path}`

let repo

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), 'go-release-artifact-'))
  git(repo, 'init', '-q', '-b', 'main')
  git(repo, 'config', 'user.name', 'test')
  git(repo, 'config', 'user.email', 'test@example.com')
  git(repo, 'config', 'commit.gpgsign', 'false')
  writeFileSync(join(repo, '.gitignore'), '*.wasm\n')
  git(repo, 'add', '.gitignore')
  git(repo, 'commit', '-q', '-m', 'source')
})

afterEach(() => {
  rmSync(repo, { recursive: true, force: true })
})

/** Put `path` in the artifact with `body`. Returns its manifest line. */
function stage(path, body) {
  const at = join(repo, 'release-out', path)
  mkdirSync(dirname(at), { recursive: true })
  writeFileSync(at, body)
  return sha256Line(at, path)
}

/** The honest manifest: one line per guest, in GUESTS order. */
function honestManifest() {
  return GUESTS.map((guest) => stage(guest, `guest ${guest}\n`))
}

function writeManifest(lines) {
  writeFileSync(
    join(repo, 'release-out/guests.sha256'),
    `${lines.join('\n')}\n`,
  )
}

/** The tree the release commit should have: HEAD plus the three guests. */
function expectedTree() {
  const index = join(repo, '.git', 'expected-index')
  const env = { ...process.env, GIT_INDEX_FILE: index }
  execFileSync('git', ['read-tree', 'HEAD'], { cwd: repo, env })
  for (const guest of GUESTS) {
    const blob = git(repo, 'hash-object', '-w', join('release-out', guest))
    execFileSync(
      'git',
      ['update-index', '--add', '--cacheinfo', `100644,${blob},${guest}`],
      { cwd: repo, env },
    )
  }
  return execFileSync('git', ['write-tree'], {
    cwd: repo,
    env,
    encoding: 'utf8',
  }).trim()
}

function runCommitStep(tree) {
  return spawnSync('bash', ['-c', String(COMMIT_STEP.run)], {
    cwd: repo,
    encoding: 'utf8',
    env: {
      PATH: `${SHIMS}:${process.env.PATH}`,
      HOME: repo,
      GIT_CONFIG_NOSYSTEM: '1',
      GUESTS: WORKFLOW.env.GUESTS,
      VERSION: '0.1.0-alpha.1',
      TREE: tree,
      GITHUB_SHA: git(repo, 'rev-parse', 'HEAD'),
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'cipherstash/stack',
      GITHUB_RUN_ID: '1',
    },
  })
}

describe.skipIf(!BASH_HAS_MAPFILE)(
  'release-golang.yml publish: Commit the guests',
  () => {
    it('exists, and the publish job takes its paths from GUESTS', () => {
      expect(COMMIT_STEP).toBeDefined()
      expect(GUESTS).toHaveLength(3)
      expect(String(COMMIT_STEP.run)).toContain('"$GUESTS"')
    })

    it.skipIf(!GNU_COREUTILS)(
      'commits the three guests from an honest artifact',
      () => {
        writeManifest(honestManifest())
        const tree = expectedTree()
        const result = runCommitStep(tree)
        expect(result.stderr + result.stdout).not.toContain('::error::')
        expect(result.status).toBe(0)
        expect(git(repo, 'rev-parse', 'HEAD^{tree}')).toBe(tree)
        expect(
          git(repo, 'show', '--name-only', '--format=', 'HEAD').split('\n'),
        ).toEqual([...GUESTS].sort())
      },
    )

    it.each([
      [
        'an extra path',
        (lines) => [
          ...lines,
          stage('languages/golang/encrypt/init.go', 'package encrypt\n'),
        ],
      ],
      [
        'a substituted path',
        (lines) => [
          lines[0],
          lines[1],
          stage('languages/golang/auth/init.go', 'package auth\n'),
        ],
      ],
      [
        'a path outside the module',
        (lines) => [
          lines[0],
          lines[1],
          stage('.github/workflows/x.yml', 'on: push\n'),
        ],
      ],
      ['a missing guest', (lines) => lines.slice(0, 2)],
      ['the guests out of order', (lines) => [lines[1], lines[0], lines[2]]],
      [
        'a BSD-format line sha256sum -c would also accept',
        (lines) => {
          const [hash, path] = lines[2].split('  ')
          return [lines[0], lines[1], `SHA256 (${path}) = ${hash}`]
        },
      ],
    ])('refuses a manifest with %s before copying anything', (_, forge) => {
      const honest = honestManifest()
      // The tree a compromised build would report for its forged manifest is
      // whatever it likes; give the step the honest tree so only the manifest
      // check can stop it.
      const tree = expectedTree()
      const head = git(repo, 'rev-parse', 'HEAD')
      writeManifest(forge(honest))

      const result = runCommitStep(tree)

      expect(result.status).not.toBe(0)
      expect(result.stdout).toContain('::error::guests.sha256')
      expect(git(repo, 'rev-parse', 'HEAD')).toBe(head)
      for (const path of [
        ...GUESTS,
        'languages/golang/encrypt/init.go',
        'languages/golang/auth/init.go',
        '.github/workflows/x.yml',
      ]) {
        expect(existsSync(join(repo, path)), path).toBe(false)
      }
    })
  },
)

/**
 * `build` reports the tree it tested and `publish` refuses any other, so the
 * two must stage the guests identically. Cargo writes them executable and
 * `publish` writes them 0644 from the artifact, which made the trees differ
 * in mode alone: the first release refused itself. Both now set the mode in
 * git (`--chmod=-x`), so it no longer depends on the files.
 */
const STAGE_STEP = WORKFLOW.jobs.build.steps.find((step) => step.id === 'stage')
const STAGE_UNTIL = 'fetched=$(mktemp -d)'

/**
 * Run the build job's staging, up to the tree it reports, on guests left
 * executable as cargo leaves them, then return to `main`. Returns the tree.
 */
function runBuildStaging() {
  const script = String(STAGE_STEP.run)
  const cut = script.indexOf(STAGE_UNTIL)
  expect(
    cut,
    `the stage step no longer contains ${STAGE_UNTIL}`,
  ).toBeGreaterThan(0)
  for (const guest of GUESTS) {
    const built = join(repo, guest)
    mkdirSync(dirname(built), { recursive: true })
    writeFileSync(built, `guest ${guest}\n`, { mode: 0o755 })
  }
  const result = spawnSync(
    'bash',
    ['-c', `${script.slice(0, cut)}\necho "$tree"`],
    {
      cwd: repo,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        HOME: repo,
        GIT_CONFIG_NOSYSTEM: '1',
        GUESTS: WORKFLOW.env.GUESTS,
        VERSION: '0.1.0-alpha.1',
      },
    },
  )
  expect(result.status, result.stderr).toBe(0)
  // Forced: the guests on disk are still 0755 while the commit holds them
  // 0644, which git reads as a local change.
  git(repo, 'checkout', '-q', '-f', 'main')
  return result.stdout.trim().split('\n').at(-1)
}

describe('release-golang.yml build: Stage the release commit', () => {
  it('commits the guests non-executable, whatever mode cargo left them in', () => {
    expect(STAGE_STEP).toBeDefined()
    const tree = runBuildStaging()
    for (const guest of GUESTS) {
      expect(git(repo, 'ls-tree', tree, guest).split(/\s+/)[0], guest).toBe(
        '100644',
      )
    }
  })
})

describe.skipIf(!BASH_HAS_MAPFILE)(
  'release-golang.yml build and publish build the same tree',
  () => {
    it.skipIf(!GNU_COREUTILS)(
      'publish accepts the tree build reports, from an executable artifact',
      () => {
        const tree = runBuildStaging()
        // The artifact executable too: the two jobs agree through git, not
        // through what either one wrote to disk.
        writeManifest(
          GUESTS.map((guest) => {
            const line = stage(guest, `guest ${guest}\n`)
            chmodSync(join(repo, 'release-out', guest), 0o755)
            return line
          }),
        )
        const result = runCommitStep(tree)
        expect(result.stderr + result.stdout).not.toContain('::error::')
        expect(result.status).toBe(0)
      },
    )
  },
)
