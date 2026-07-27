import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

const REPO_ROOT = resolve(import.meta.dirname, '..')

// Default targets — the surfaces a reader or agent navigates by. Override with
// argv[2..] for tests / ad-hoc checks.
//
// Deliberately NOT scanned:
//  - `docs/plans/`, `docs/superpowers/` — design archives. They narrate the
//    state of the tree at the time they were written, including packages the
//    plan itself proposed removing. Rewriting history there is wrong.
//  - `CHANGELOG.md` (anywhere) — released entries name what they removed.
const TARGETS = process.argv.slice(2).length
  ? process.argv.slice(2)
  : [
      'AGENTS.md',
      'CLAUDE.md',
      'README.md',
      'SECURITY.md',
      'CONTRIBUTE.md',
      'docs',
      '.github',
      'skills',
      'e2e/README.md',
      'packages/cli/AGENTS.md',
      // The linters themselves carry package paths — an allowlist entry for a
      // deleted package sat here unnoticed because `scripts/` was not scanned.
      // `__tests__` is excluded below: its fixtures MUST name dead packages.
      'scripts',
    ]

const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  'plans',
  'superpowers',
  '.git',
  // This linter's own self-tests deliberately reference deleted packages —
  // in the fixtures, and in the prose comments of the test files themselves.
  // Scanning them would make the suite unrunnable.
  '__tests__',
])
const SKIP_FILES = new Set(['CHANGELOG.md'])
const TEXT_EXT = /\.(md|ya?ml|json|mjs|ts|txt)$/

// `packages/<name>` where `<name>` is a real directory name. The character
// class excludes `*`, so workspace globs (`packages/*`, `./packages/*`) are
// left alone, and it is greedy so a longer directory name is never excused by
// a live package whose name is a prefix of it.
//
// The name must END on an alphanumeric. Without that anchor a sentence-final
// `packages/stack.` — or a hyphen at a line wrap, or a trailing underscore —
// captured the punctuation too and reported a LIVE package as dead, failing
// the build with a message naming a directory that plainly exists. Uppercase
// is admitted so a capitalised directory name is checked rather than silently
// skipped; no package uses one today, which is exactly why nothing noticed
// (#772 review, finding 15).
const PACKAGE_REF = /packages\/([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?)/g

// Live packages come from git, not from what is on disk.
//
// `readdirSync` was wrong in the direction that matters: deleting a package
// leaves its `dist/` and `node_modules/` behind, so the directory still exists
// and every reference to the deleted package passed. That is the exact failure
// this linter was written to catch, and it silently stopped catching it on any
// checkout where the package had previously been built — two packages deleted
// by this very stack are sitting on `main` right now as exactly such shells
// (#772 review, finding 15).
//
// Note this deliberately does NOT require a `package.json`: `packages/utils` has
// none (it is two loose files consumed by relative path from `packages/nextjs`)
// yet is tracked, live, and referenced from AGENTS.md.
//
// Shelling out to git is a dependency this linter has to own: git missing, or a
// tree with no `.git`, must not read as "every package is dead".
function gitPackagePaths(...args) {
  try {
    return execFileSync('git', args, {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    })
      .split('\0')
      .filter(Boolean)
  } catch (err) {
    const detail = String(err.stderr || err.message || '').trim()
    console.error(
      `Could not list packages via \`git ${args.join(' ')}\`:\n\n  ${detail}\n\n` +
        'This linter derives the live package set from git, so it cannot run\n' +
        'without git on PATH or outside a git checkout.',
    )
    // Exit 2, not 1: the linter failed to run. Exit 1 means it ran and found
    // dead references, which is a different thing to go and fix.
    process.exit(2)
  }
}

const livePackages = new Set(
  [
    ...gitPackagePaths('ls-files', '-z', 'packages'),
    // Untracked but not ignored. A package scaffolded a minute ago is live
    // even though nothing about it is staged yet, and reporting it as "does
    // not exist" is the sentence-final false alarm all over again, pointed the
    // other way. `--directory` is deliberately NOT passed: it collapses an
    // all-ignored directory to a single entry, which would resurrect exactly
    // the `dist/`-and-`node_modules/` shells this linter exists to catch.
    ...gitPackagePaths(
      'ls-files',
      '--others',
      '--exclude-standard',
      '-z',
      'packages',
    ),
  ]
    .map((file) => file.split('/')[1])
    .filter(Boolean),
)

if (livePackages.size === 0) {
  console.error(
    'git reported no packages at all under `packages/`. Refusing to run —\n' +
      'every reference would be flagged. Check that `packages/` is present and\n' +
      'not wholly ignored.',
  )
  process.exit(2)
}

function* walk(abs) {
  const stat = statSync(abs)
  if (stat.isFile()) {
    yield abs
    return
  }
  for (const entry of readdirSync(abs, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue
      yield* walk(join(abs, entry.name))
    } else if (!SKIP_FILES.has(entry.name) && TEXT_EXT.test(entry.name)) {
      yield join(abs, entry.name)
    }
  }
}

const offenders = []
for (const target of TARGETS) {
  const abs = resolve(REPO_ROOT, target)
  let exists = true
  try {
    statSync(abs)
  } catch {
    exists = false
  }
  // A target that isn't there used to be skipped in silence, on the theory
  // that the default list covered optional files. It doesn't — all of TARGETS
  // is tracked and present — and the silence was the same rot this linter
  // exists to catch, one level up: rename a target and it drops out of
  // coverage forever with a green build. `lint-no-hardcoded-runners.mjs`
  // already exits 2 on a stale allowlist entry; this is that rule applied to
  // this linter's own configuration.
  if (!exists) {
    console.error(
      `Target \`${target}\` does not exist.\n\n` +
        'Either it was renamed or removed — in which case update TARGETS in\n' +
        'this script, since a target that is silently skipped is coverage\n' +
        'quietly lost — or it was mistyped on the command line.',
    )
    // Exit 2, not 1: the linter could not check what it was asked to check.
    process.exit(2)
  }

  for (const file of walk(abs)) {
    // A target outside the repo (only reachable via an argv override — every
    // default is repo-relative) renders as a `../../../../..` chain climbing
    // out of the root, which buries the filename it exists to point at.
    const rel = relative(REPO_ROOT, file)
    const shown = rel.startsWith('..') ? file : rel
    if (SKIP_FILES.has(rel.split('/').pop())) continue
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, idx) => {
      PACKAGE_REF.lastIndex = 0
      for (const m of line.matchAll(PACKAGE_REF)) {
        if (livePackages.has(m[1])) continue
        offenders.push(
          `${shown}:${idx + 1}: \`packages/${m[1]}\` does not exist`,
        )
      }
    })
  }
}

if (offenders.length > 0) {
  console.error(
    `Found ${offenders.length} reference(s) to a non-existent package directory:\n`,
  )
  for (const o of offenders) console.error(`  ${o}`)
  console.error(
    '\nA package was renamed or removed without updating the docs and config\n' +
      'that point at it. Repoint each reference at the surviving path, or drop\n' +
      'the line if it no longer describes anything. Design archives\n' +
      '(docs/plans, docs/superpowers) and CHANGELOGs are exempt — they record\n' +
      'history, not the current tree.',
  )
  process.exit(1)
}
