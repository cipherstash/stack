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
  // Fixtures for this linter's own self-tests deliberately reference deleted
  // packages; scanning them would make the suite unrunnable.
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

// Live packages come from what git TRACKS, not from what is on disk.
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
const livePackages = new Set(
  execFileSync('git', ['ls-files', '-z', 'packages'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
    .split('\0')
    .filter(Boolean)
    .map((file) => file.split('/')[1])
    .filter(Boolean),
)

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
  // A default target that doesn't exist is not an error — the list covers
  // optional files (CONTRIBUTE.md, per-package AGENTS.md).
  if (!exists) continue

  for (const file of walk(abs)) {
    const rel = relative(REPO_ROOT, file)
    if (SKIP_FILES.has(rel.split('/').pop())) continue
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, idx) => {
      PACKAGE_REF.lastIndex = 0
      for (const m of line.matchAll(PACKAGE_REF)) {
        if (livePackages.has(m[1])) continue
        offenders.push(`${rel}:${idx + 1}: \`packages/${m[1]}\` does not exist`)
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
