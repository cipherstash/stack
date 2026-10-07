/**
 * The Go module's release line: is a release owed, and cutting it.
 *
 * WHY EACH RELEASE TAGS A COMMIT OF ITS OWN. The module
 * (`github.com/cipherstash/stack/languages/golang`) embeds WASI guests built
 * from the Rust crates (`//go:embed wasm`). The built guests are gitignored on
 * main, and Go fetches a module from the git tree at its tag, so a tag on a
 * commit of main would give `go get` a module with no guests in it, failing on
 * first use with `ErrGuestNotBuilt`. A release therefore tags a commit made
 * for it: the commit that set the version, plus the built guests and nothing
 * else. Main never holds a binary. A module fetched at a commit of main (`@main`
 * or a pseudo-version) has no guests either: only tagged versions run.
 *
 * WHO DECIDES THE VERSION: Changesets, through the private placeholder
 * `languages/golang/package.json` (`@cipherstash/golang`). It is never
 * published. It exists so a changeset can name the Go module, and so the
 * Version Packages PR moves its version and writes its CHANGELOG like any other
 * package's. `0.0.0` means the module has had no release.
 *
 * THE ANSWER COMES FROM THE TAGS, as for EQL's assets (eql-release-assets.mjs):
 * a release is owed when the tree's version has no `languages/golang/v<version>`
 * tag. It is built at the commit that set that version, found from git, so a
 * re-run after a failure builds the same source whatever merged since.
 *
 * NOTHING IS PUBLIC UNTIL IT HAS BEEN CHECKED. Go's checksum database records a
 * version the first time anyone fetches it, so a published tag can never be
 * moved or reused; a bad one costs a version number. Before the tag exists:
 * the guests are built twice, on separate runners, and must be identical byte
 * for byte; the release commit is made on a scratch branch; and the module is
 * downloaded from that commit with the go command, to show the guests are in
 * what `go get` will receive.
 *
 * A DRY RUN (`DRY_RUN=true`, the workflow's `dry_run` dispatch input) does all
 * of that at the dispatched commit, up to and including the download, then
 * deletes the scratch branch: no tag, no GitHub release. It is how the line is
 * exercised before a version is spent on it.
 *
 * Subcommands, one per job of .github/workflows/release-golang.yml (the guests
 * are built by scripts/golang-release-build.mjs, which runs the mise tasks):
 *
 *   plan                     is a release owed, and at which commit
 *   publish <first> <second> compare the two builds, make and check the release
 *                            commit, push the tag, write the GitHub release and
 *                            fetch the version through the Go proxy
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  appendFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { tagCommitVia } from './eql-release-assets.mjs'

const REPO_ROOT = resolve(import.meta.dirname, '..')

export const GO_MODULE = 'github.com/cipherstash/stack/languages/golang'
export const GO_ROOT = 'languages/golang'
export const GO_MANIFEST = `${GO_ROOT}/package.json`
export const GO_CHANGELOG = `${GO_ROOT}/CHANGELOG.md`
export const GO_PACKAGE = '@cipherstash/golang'
/** The placeholder's version until the first Go changeset is versioned. */
export const UNRELEASED = '0.0.0'

/**
 * Every guest the module embeds: the root mise task that builds it and copies
 * it into the module, and the file it writes there.
 *
 * scripts/__tests__/golang-release.test.mjs holds this list to the module's
 * `//go:embed wasm` directories and to the tasks in mise.toml, so a guest
 * added, moved or renamed fails there instead of shipping a module without it.
 */
export const GUESTS = [
  {
    task: 'wasm:guest:build',
    path: `${GO_ROOT}/stackencrypt/wasm/stack_encrypt_guest.wasm`,
  },
  {
    task: 'wasm:auth-guest:build',
    path: `${GO_ROOT}/stackauth/wasm/stack_auth_guest.wasm`,
  },
]

/**
 * The versions this may name. It ends up in a tag, a branch, a commit message
 * and a release name, so anything else is refused here.
 */
const VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/

/** Go reads a module's versions in a subdirectory from tags under its path. */
export const releaseTag = (version) => `${GO_ROOT}/v${version}`
/** Where the release commit is made before it is checked and tagged. */
export const scratchBranch = (version, dryRun = false) =>
  `release-golang/${dryRun ? 'dry-run/' : ''}v${version}`

export const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex')

/**
 * Is a release owed for `version`, and at which commit?
 *
 * `tagCommit(tag)` and `versionCommit(version)` are asked lazily, in that
 * order, so a version already tagged costs no history walk.
 */
function checkVersion(version) {
  if (!VERSION.test(version)) {
    throw new Error(
      `${GO_MANIFEST} carries version \`${version}\`, which is not X.Y.Z or X.Y.Z-pre`,
    )
  }
}

export function goRelease({ version, tagCommit, versionCommit }) {
  checkVersion(version)
  const tag = releaseTag(version)
  const prerelease = version.includes('-')
  const none = (reason) => ({
    needed: false,
    version,
    tag,
    prerelease,
    ref: '',
    reason,
  })

  if (version === UNRELEASED) {
    return none(
      `${GO_MANIFEST} is at ${UNRELEASED}: the Go module has had no release, ` +
        `and gets its first when a changeset naming ${GO_PACKAGE} is versioned`,
    )
  }

  const tagged = tagCommit(tag)
  if (tagged) return none(`${tag} already exists at ${tagged}`)

  const ref = versionCommit(version)
  return {
    needed: true,
    version,
    tag,
    prerelease,
    ref,
    reason: `${tag} does not exist; building ${version} at ${ref}, the commit that set it`,
  }
}

/**
 * A dry run builds the dispatched commit whatever the version and the tags
 * say: it tags nothing, so nothing it does can be owed or repeated.
 */
export function dryRunPlan({ version, head }) {
  checkVersion(version)
  return {
    needed: true,
    version,
    tag: releaseTag(version),
    prerelease: version.includes('-'),
    ref: head,
    reason: `dry run: building ${version} at ${head}; nothing will be tagged`,
  }
}

function git(...args) {
  return execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8' }).trim()
}

/**
 * The commit that set the manifest's version: the last one to change its
 * `"version"` line. Checked against the version asked for, so a history that
 * says otherwise is refused rather than built.
 */
export function versionCommitVia(run = git) {
  return (version) => {
    if (run('rev-parse', '--is-shallow-repository') === 'true') {
      throw new Error(
        'the checkout is shallow, so the commit that set the version cannot be ' +
          'found; check out with `fetch-depth: 0`',
      )
    }
    const sha = run(
      'log',
      '-1',
      '--format=%H',
      '-G',
      '"version"',
      '--',
      GO_MANIFEST,
    )
    if (!sha) throw new Error(`no commit changes the version in ${GO_MANIFEST}`)
    const set = JSON.parse(run('show', `${sha}:${GO_MANIFEST}`)).version
    if (set !== version) {
      throw new Error(
        `the last commit to change the version in ${GO_MANIFEST}, ${sha}, sets ${set}, not ${version}`,
      )
    }
    return sha
  }
}

/**
 * The guests of two builds, which must be identical byte for byte. A
 * difference means the build is not reproducible, and nothing is tagged.
 */
export function compareBuilds(first, second, read = readFileSync) {
  return GUESTS.map(({ path }) => {
    const [a, b] = [first, second].map((dir) => {
      try {
        return read(join(dir, path))
      } catch (err) {
        throw new Error(
          `${path} is missing from the build in ${dir}: ${err.message}`,
        )
      }
    })
    const [hashA, hashB] = [sha256(a), sha256(b)]
    if (hashA !== hashB) {
      throw new Error(
        `the two builds of ${path} differ (${hashA} and ${hashB}); a release ` +
          'must be reproducible, so nothing was tagged',
      )
    }
    return { path, bytes: a, sha256: hashA }
  })
}

/** The body of one version's section of a Changesets CHANGELOG. */
export function changelogSection(text, version) {
  const lines = text.split('\n')
  const start = lines.findIndex((line) => line.trim() === `## ${version}`)
  if (start === -1) {
    throw new Error(`${GO_CHANGELOG} has no \`## ${version}\` section`)
  }
  const rest = lines.slice(start + 1)
  const end = rest.findIndex((line) => line.startsWith('## '))
  return (end === -1 ? rest : rest.slice(0, end)).join('\n').trim()
}

export function releaseNotes({ version, section, ref, guests }) {
  return [
    section,
    '',
    '## Install',
    '',
    '```',
    `go get ${GO_MODULE}@v${version}`,
    '```',
    '',
    '## Embedded guests',
    '',
    `Built twice, on separate runners, from ${ref} (the commit that set this ` +
      'version), and identical byte for byte. The tag points at a commit on top ' +
      'of it that adds these files and nothing else:',
    '',
    '| File | SHA-256 |',
    '| --- | --- |',
    ...guests.map(({ path, sha256: hash }) => `| \`${path}\` | \`${hash}\` |`),
    '',
  ].join('\n')
}

const CREATE_COMMIT = `mutation ($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid } }
}`

/**
 * Make the release commit on a scratch branch, check it, tag it, and write
 * the GitHub release. Nothing is public until `verify` has passed. A dry run
 * stops after `verify`, and only deletes the branch.
 *
 * The commit is made with `createCommitOnBranch` rather than pushed, so GitHub
 * signs it, and with `expectedHeadOid` so its only parent is `ref`.
 */
export function publish({
  repo,
  version,
  tag,
  ref,
  prerelease,
  guests,
  notes,
  api,
  graphql,
  tagCommit,
  verify,
  dryRun = false,
}) {
  const tagged = dryRun ? null : tagCommit(tag)
  if (tagged) {
    throw new Error(
      `${tag} appeared at ${tagged} after this run planned the release; nothing was changed`,
    )
  }

  const branch = scratchBranch(version, dryRun)
  const existing = api('GET', `repos/${repo}/git/matching-refs/heads/${branch}`)
  if (existing.some((entry) => entry.ref === `refs/heads/${branch}`)) {
    // Left by a run that failed before deleting it. It belongs to this line.
    api('PATCH', `repos/${repo}/git/refs/heads/${branch}`, {
      sha: ref,
      force: true,
    })
  } else {
    api('POST', `repos/${repo}/git/refs`, {
      ref: `refs/heads/${branch}`,
      sha: ref,
    })
  }

  let commit
  try {
    commit = graphql(CREATE_COMMIT, {
      input: {
        branch: { repositoryNameWithOwner: repo, branchName: branch },
        expectedHeadOid: ref,
        message: {
          headline: `chore(release): Go module v${version}`,
          body:
            `The embedded guests for ${tag}, built from ${ref}.\n\n` +
            guests
              .map(({ path, sha256: hash }) => `${hash}  ${path}`)
              .join('\n'),
        },
        fileChanges: {
          additions: guests.map(({ path, bytes }) => ({
            path,
            contents: Buffer.from(bytes).toString('base64'),
          })),
        },
      },
    }).createCommitOnBranch.commit.oid

    verify(commit, guests)
    if (!dryRun) {
      api('POST', `repos/${repo}/git/refs`, {
        ref: `refs/tags/${tag}`,
        sha: commit,
      })
    }
  } finally {
    api('DELETE', `repos/${repo}/git/refs/heads/${branch}`)
  }
  if (dryRun) return commit

  api('POST', `repos/${repo}/releases`, {
    tag_name: tag,
    name: `Go module v${version}`,
    body: notes,
    prerelease,
    // The repository's latest release is an npm or EQL one; a Go release must
    // not take that place.
    make_latest: 'false',
  })
  return commit
}

function go(args, env) {
  const cwd = mkdtempSync(join(tmpdir(), 'golang-release-'))
  try {
    return execFileSync('go', args, {
      cwd,
      encoding: 'utf8',
      env: {
        ...process.env,
        GOMODCACHE: join(cwd, 'modcache'),
        GOFLAGS: '-modcacherw',
        ...env,
      },
    })
  } finally {
    rmSync(cwd, { recursive: true, force: true })
  }
}

/**
 * Download the module at `query` with the go command and check every guest in
 * it is the one that was built. `env` picks the source: straight from GitHub
 * before the tag exists (a commit is no version the checksum database knows),
 * through the public proxy after.
 */
export function verifyModuleVia(env, run = go) {
  return (query, guests) => {
    const info = JSON.parse(
      run(['mod', 'download', '-json', `${GO_MODULE}@${query}`], env),
    )
    if (info.Error)
      throw new Error(`go mod download ${GO_MODULE}@${query}: ${info.Error}`)
    for (const { path, sha256: hash } of guests) {
      const file = join(info.Dir, path.slice(GO_ROOT.length + 1))
      let got
      try {
        got = sha256(readFileSync(file))
      } catch {
        throw new Error(`the module at ${query} has no ${path}`)
      }
      if (got !== hash) {
        throw new Error(
          `the module at ${query} carries ${path} as ${got}, not ${hash}`,
        )
      }
    }
  }
}

export const DIRECT = { GOPROXY: 'direct', GOSUMDB: 'off' }
export const PROXY = {
  GOPROXY: 'https://proxy.golang.org',
  GOSUMDB: 'sum.golang.org',
}

function gh(args, body) {
  const dir = mkdtempSync(join(tmpdir(), 'golang-release-gh-'))
  try {
    const input = []
    if (body !== undefined) {
      const file = join(dir, 'body.json')
      writeFileSync(file, JSON.stringify(body))
      input.push('--input', file)
    }
    const out = execFileSync('gh', ['api', ...args, ...input], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    })
    return out.trim() ? JSON.parse(out) : null
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

const api = (method, path, body) => gh(['--method', method, path], body)

function graphql(query, variables) {
  const { data, errors } = gh(['graphql'], { query, variables })
  if (errors?.length) throw new Error(errors.map((e) => e.message).join('; '))
  return data
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

/** Retry `fn` while the proxy catches up with a tag it has not seen yet. */
export function eventually(
  fn,
  { attempts = 6, delay = 20_000, wait = sleep } = {},
) {
  for (let attempt = 1; ; attempt++) {
    try {
      return fn()
    } catch (err) {
      if (attempt === attempts) throw err
      console.log(`attempt ${attempt} of ${attempts}: ${err.message}`)
      wait(delay)
    }
  }
}

function required(name) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is not set`)
  return value
}

const manifestVersion = () =>
  JSON.parse(readFileSync(join(REPO_ROOT, GO_MANIFEST), 'utf8')).version

const isDryRun = () => process.env.DRY_RUN === 'true'

function plan() {
  const result = isDryRun()
    ? dryRunPlan({ version: manifestVersion(), head: required('GITHUB_SHA') })
    : goRelease({
        version: manifestVersion(),
        tagCommit: tagCommitVia(required('REPO')),
        versionCommit: versionCommitVia(),
      })
  console.log(result.reason)
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `needed=${result.needed}\nversion=${result.version}\ntag=${result.tag}\n` +
        `prerelease=${result.prerelease}\nref=${result.ref}\n`,
    )
  }
}

function release(first, second) {
  const repo = required('REPO')
  const version = required('VERSION')
  const ref = required('REF')
  // The checkout is `ref`, so its manifest must agree with the plan.
  if (manifestVersion() !== version) {
    throw new Error(
      `${GO_MANIFEST} at this checkout is not ${version}; check out ${ref}`,
    )
  }
  const dryRun = isDryRun()
  const guests = compareBuilds(first, second)
  const notes = releaseNotes({
    version,
    section: dryRun
      ? '(A dry run: the changelog is not read.)'
      : changelogSection(
          readFileSync(join(REPO_ROOT, GO_CHANGELOG), 'utf8'),
          version,
        ),
    ref,
    guests,
  })
  const tag = releaseTag(version)
  const commit = publish({
    repo,
    version,
    tag,
    ref,
    prerelease: version.includes('-'),
    guests,
    notes,
    api,
    graphql,
    tagCommit: tagCommitVia(repo),
    verify: verifyModuleVia(DIRECT),
    dryRun,
  })
  if (dryRun) {
    console.log(
      `dry run: ${commit}, on top of ${ref}, carries the built guests in what ` +
        '`go get` receives; the scratch branch is deleted and nothing was tagged.\n' +
        `The release notes would read:\n\n${notes}`,
    )
    return
  }
  console.log(`tagged ${tag} at ${commit}, on top of ${ref}`)

  // The tag is public now; this asks proxy.golang.org (and through it the
  // checksum database) for the version, which lists it on pkg.go.dev, and
  // checks what the proxy serves. A failure here cannot be undone by this job.
  eventually(() => verifyModuleVia(PROXY)(`v${version}`, guests))
  console.log(
    `proxy.golang.org serves ${GO_MODULE}@v${version} with the built guests`,
  )
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [command, ...args] = process.argv.slice(2)
    if (command === 'plan') plan()
    else if (command === 'publish' && args.length === 2) release(...args)
    else
      throw new Error(
        'usage: golang-release.mjs plan | publish <first> <second>',
      )
  } catch (err) {
    console.error(`::error::${err.message}`)
    process.exit(1)
  }
}
