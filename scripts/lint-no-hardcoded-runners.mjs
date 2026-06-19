import { readFileSync, statSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'

const REPO_ROOT = resolve(import.meta.dirname, '..')

// Files that legitimately contain a `npx` literal — keep this list
// short and explicit so additions require deliberate review.
const ALLOWLISTED_PATHS = new Set([
  'packages/wizard/src/lib/detect.ts', // npm row of the PM table
  'packages/cli/src/commands/init/utils.ts', // runnerCommand `case 'npm'`
  'packages/cli/src/commands/init/lib/setup-prompt.ts', // execCommand `case 'npm':` switch
  'packages/protect/src/bin/runner.ts', // Pre-allowlisted: helper for Task 11
  'packages/drizzle/src/bin/runner.ts', // Pre-allowlisted: helper for Task 13
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
  const entries = await readdir(dir, { withFileTypes: true })
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

const offenders = []
for (const target of TARGETS) {
  const abs = resolve(REPO_ROOT, target)
  const stat = statSync(abs)
  const files = stat.isDirectory() ? walk(abs) : [abs]
  for await (const file of files) {
    const rel = relative(REPO_ROOT, file)
    if (ALLOWLISTED_PATHS.has(rel)) continue
    if (/\.(test|spec)\.(ts|tsx|mts|cts)$/.test(file)) continue
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, idx) => {
      const matches = NPX_TOKEN.test(line)
      if (!matches) return
      if (isCommentLine(line)) return
      if (isAllowedFallback(line)) return
      if (isAllowedRunnerSwitch(line)) return
      offenders.push(`${rel}:${idx + 1}: ${line.trim()}`)
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
