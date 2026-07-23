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
    ]

const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  'plans',
  'superpowers',
  '.git',
])
const SKIP_FILES = new Set(['CHANGELOG.md'])
const TEXT_EXT = /\.(md|ya?ml|json|mjs|ts|txt)$/

// `packages/<name>` where `<name>` is a real directory name. The character
// class excludes `*`, so workspace globs (`packages/*`, `./packages/*`) are
// left alone, and `+` is greedy so `packages/stack-forge` is never excused by
// the live `packages/stack`.
const PACKAGE_REF = /packages\/([a-z0-9][a-z0-9._-]*)/g

const livePackages = new Set(
  readdirSync(resolve(REPO_ROOT, 'packages'), { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name),
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
