import { readFileSync, statSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'

const REPO_ROOT = resolve(import.meta.dirname, '..')

// Files that legitimately contain a `npx` literal — keep this list
// short and explicit so additions require deliberate review.
const ALLOWLISTED_PATHS = new Set([
  'packages/wizard/src/lib/detect.ts', // npm row of the PM table
  'packages/cli/src/commands/init/utils.ts', // runnerCommand `case 'npm'`
  'scripts/lint-no-hardcoded-runners.mjs', // this script's own docs
])

// Default scan root; override with argv[2] for tests.
const TARGETS = process.argv.slice(2).length
  ? process.argv.slice(2)
  : ['packages']

// Catches:
//   - `'npx'` / `"npx"` / `` `npx `` — bare-quoted, e.g. `?? 'npx'` or `runner = 'npx'`
//   - `Usage: npx @cipherstash/cli` and any string content where `npx`
//     precedes a command (`npx ` followed by an id-like char `[@\w-]`),
//     including continuation lines inside multi-line template literals.
// `npx` as a JS identifier (e.g. `npxResult`, `let npx = 5`) is NOT matched
// because the second alternative requires whitespace+id after the token, and
// the first requires a surrounding quote.
const NPX_TOKEN = /['"`]npx\b|(?:^|[^a-zA-Z0-9_$])npx\s+[@\w-]/

async function* walk(dir) {
  // A directory can vanish between the parent's `readdir` and this call. The
  // repo's own script self-tests create and delete probe packages under
  // `packages/` (`lint-untracked-probe`, `lint-dead-shell-probe` in
  // `lint-no-dead-package-paths.test.mjs`) while other suites run, so a walk of
  // `packages/` can enumerate one and find it gone a moment later.
  //
  // Left unhandled this rejects with ENOENT, and Node exits **1** — the same
  // code as "found a hardcoded npx". Every caller then reads a crash as a
  // violation: CI fails naming a file that is perfectly clean, and re-running
  // it passes. The missing-target case deliberately exits 2 for exactly this
  // reason ("Exit 2 means the linter could not run"); this is the same
  // distinction, one level down. There is nothing to lint in a directory that
  // no longer exists, so skip it.
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch (err) {
    if (err?.code === 'ENOENT') return
    throw err
  }
  for (const entry of entries) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (
        entry.name === 'node_modules' ||
        entry.name === 'dist' ||
        entry.name === '.turbo' ||
        entry.name === '__tests__'
      )
        continue
      yield* walk(full)
    } else if (/\.(ts|tsx|mts|cts)$/.test(entry.name)) {
      if (/\.(test|spec)\.(ts|tsx|mts|cts)$/.test(entry.name)) continue
      yield full
    }
  }
}

function isCommentLine(line) {
  const trimmed = line.trim()
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('/**')
  )
}

function isAllowedFallback(line) {
  // Runtime fallback when detection returns undefined: `?? 'npx'`
  return /\?\?\s*['"`]npx['"`]/.test(line)
}

function isAllowedRunnerSwitch(line) {
  // `case 'npm': return \`npx ${...}\`` style — only in the canonical helper
  return /\bcase\s+['"]npm['"]/.test(line) || /name:\s*['"]npm['"]/.test(line)
}

// An allowlist entry is a standing exemption, so it has to keep earning its
// place. Two ways it rots: the file is deleted (which is how the legacy Drizzle
// package's `src/bin/runner.ts` entry outlived its package by two months), or
// the file survives but the `npx` literal it was excused for moves elsewhere —
// leaving an entry that reads as evidence the exemption is still needed. Check
// both before scanning anything.
const staleAllowlist = []
for (const rel of ALLOWLISTED_PATHS) {
  let source
  try {
    source = readFileSync(resolve(REPO_ROOT, rel), 'utf8')
  } catch {
    staleAllowlist.push(`${rel}: no such file`)
    continue
  }
  const stillNeeded = source
    .split('\n')
    .some(
      (line) =>
        NPX_TOKEN.test(line) &&
        !isCommentLine(line) &&
        !isAllowedFallback(line) &&
        !isAllowedRunnerSwitch(line),
    )
  if (!stillNeeded) {
    staleAllowlist.push(
      `${rel}: no longer contains an unexcused \`npx\` literal`,
    )
  }
}

if (staleAllowlist.length > 0) {
  console.error(
    `Found ${staleAllowlist.length} stale allowlist entr(ies) in this script:\n`,
  )
  for (const s of staleAllowlist) console.error(`  ${s}`)
  console.error(
    '\nDrop the entry. An exemption for a file that no longer exists, or that\n' +
      'no longer contains the literal it was excused for, is dead weight that\n' +
      'reads as deliberate.',
  )
  // Exit 2, not 1: the linter's own configuration is wrong, which is a
  // different thing to fix than an `npx` literal in the codebase.
  process.exit(2)
}

const offenders = []
for (const target of TARGETS) {
  const abs = resolve(REPO_ROOT, target)
  let stat
  try {
    stat = statSync(abs)
  } catch {
    // Was an uncaught throw: exit 1 plus a raw stack trace, which reads to
    // anything checking the exit code exactly like a genuine `npx` finding.
    // Exit 2 says the linter could not run — the same contract the allowlist
    // self-check above already uses.
    console.error(
      `Target \`${target}\` does not exist.\n\n` +
        'Update the scan roots in this script if it was renamed or removed,\n' +
        'or check the path passed on the command line.',
    )
    process.exit(2)
  }
  const files = stat.isDirectory() ? walk(abs) : [abs]
  for await (const file of files) {
    // `rel` stays repo-relative for the allowlist lookup; only the rendering
    // falls back to the absolute path, for a target outside the repo root that
    // would otherwise print a `../../../../..` chain instead of a filename.
    const rel = relative(REPO_ROOT, file)
    const shown = rel.startsWith('..') ? file : rel
    if (ALLOWLISTED_PATHS.has(rel)) continue
    if (/\.(test|spec)\.(ts|tsx|mts|cts)$/.test(file)) continue
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, idx) => {
      const matches = NPX_TOKEN.test(line)
      if (!matches) return
      if (isCommentLine(line)) return
      if (isAllowedFallback(line)) return
      if (isAllowedRunnerSwitch(line)) return
      offenders.push(`${shown}:${idx + 1}: ${line.trim()}`)
    })
  }
}

if (offenders.length > 0) {
  console.error(`Found ${offenders.length} hardcoded \`npx\` reference(s):\n`)
  for (const o of offenders) console.error(`  ${o}`)
  console.error(
    '\nUse the detected package manager instead. See ' +
      'packages/cli/src/commands/init/utils.ts (runnerCommand) and ' +
      'packages/wizard/src/lib/detect.ts (detectPackageManager).',
  )
  process.exit(1)
}

console.log('OK — no hardcoded `npx` in user-facing strings.')
