// Run by .github/workflows/require-auth-npm-changeset.yml, which decides when
// a pull request changes what @cipherstash/auth ships.
//
// Two modes:
//
//   node scripts/check-auth-npm-changeset.mjs --shipped <base-sha> < paths
//     Prints the paths, of those changed under the workflow's pathspec, that
//     can change a published @cipherstash/auth package.
//
//   node scripts/check-auth-npm-changeset.mjs <changeset>...
//     Fails unless one of the changesets releases @cipherstash/auth.
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import { basename, posix } from 'node:path'
import { fileURLToPath } from 'node:url'
import parseChangeset from '@changesets/parse'

const AUTH = 'languages/typescript/packages/auth'
const AUTH_WASM = 'languages/typescript/packages/stack-auth-wasm'

// Paths inside the binding folders that no published tarball contains and no
// build reads. Everything not listed here ships, so a new file is release
// relevant until someone decides otherwise: a path missing from this list
// costs a changeset, a path wrongly on it ships a change with no release.
const NEVER_SHIPPED = [
  `${AUTH}/__tests__/`,
  `${AUTH}/examples/`,
  `${AUTH}/vitest.config.ts`,
  `${AUTH}/tsconfig.json`,
]

// A manifest whose only change is to these fields publishes nothing new: npm
// never installs a published package's devDependencies.
const UNSHIPPED_MANIFEST_FIELDS = ['devDependencies']

const MANIFESTS = new Set([`${AUTH}/package.json`, `${AUTH_WASM}/package.json`])

const isManifest = (path) =>
  MANIFESTS.has(path) ||
  (posix.basename(path) === 'package.json' &&
    posix.dirname(posix.dirname(path)) === `${AUTH}/platforms`)

const withoutUnshippedFields = (manifest) => {
  const rest = { ...manifest }
  for (const field of UNSHIPPED_MANIFEST_FIELDS) delete rest[field]
  return JSON.stringify(rest)
}

/**
 * Whether a changed path can change a published @cipherstash/auth package.
 * `readBase` and `readHead` return a file's contents on either side of the
 * pull request, or `undefined` where it does not exist.
 */
export const isShipped = (path, { readBase, readHead }) => {
  if (
    NEVER_SHIPPED.some((prefix) => path === prefix || path.startsWith(prefix))
  )
    return false
  if (!isManifest(path)) return true

  const [base, head] = [readBase(path), readHead(path)]
  if (base === undefined || head === undefined) return true
  try {
    return (
      withoutUnshippedFields(JSON.parse(base)) !==
      withoutUnshippedFields(JSON.parse(head))
    )
  } catch {
    return true
  }
}

const gitReader = (baseSha) => (path) => {
  try {
    return execFileSync('git', ['show', `${baseSha}:${path}`], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
  } catch {
    return undefined
  }
}

const fsReader = (path) =>
  fs.existsSync(path) ? fs.readFileSync(path, 'utf8') : undefined

const printShipped = (baseSha) => {
  const readers = { readBase: gitReader(baseSha), readHead: fsReader }
  const shipped = fs
    .readFileSync(0, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .filter((path) => isShipped(path, readers))
  if (shipped.length > 0) console.log(shipped.join('\n'))
}

const requireAuthRelease = (files) => {
  // The workflow's `.changeset/*.md` pathspec matches the README, which has no
  // frontmatter.
  const changesetFiles = files
    .filter(Boolean)
    .filter((file) => basename(file) !== 'README.md')

  if (changesetFiles.length === 0) {
    console.error(
      "::error::Release-relevant stack-auth changes require an @cipherstash/auth changeset. Run 'pnpm changeset' and commit the generated file.",
    )
    process.exit(1)
  }

  let hasAuthRelease = false

  for (const changesetFile of changesetFiles) {
    const contents = fs.readFileSync(changesetFile, 'utf8')
    const lines = contents.split(/\r?\n/)
    const closingDelimiter = lines.indexOf('---', 1)

    if (lines[0] !== '---' || closingDelimiter === -1) {
      console.error(
        `::error file=${changesetFile}::Changeset must start with YAML frontmatter delimited by ---`,
      )
      process.exit(1)
    }

    if (
      lines
        .slice(closingDelimiter + 1)
        .join('\n')
        .trim().length === 0
    ) {
      console.error(
        `::error file=${changesetFile}::Changeset summary must not be empty`,
      )
      process.exit(1)
    }

    let changeset
    try {
      changeset = parseChangeset(contents)
    } catch (error) {
      console.error(
        `::error file=${changesetFile}::Invalid changeset: ${error.message}`,
      )
      process.exit(1)
    }

    if (
      changeset.releases.some(
        ({ name, type }) =>
          name === '@cipherstash/auth' &&
          (type === 'patch' || type === 'minor' || type === 'major'),
      )
    ) {
      hasAuthRelease = true
      console.log(
        `Found valid @cipherstash/auth release intent in ${changesetFile}`,
      )
    }
  }

  if (!hasAuthRelease) {
    console.error(
      "::error::Release-relevant stack-auth changes require an @cipherstash/auth changeset with a patch, minor, or major bump. Run 'pnpm changeset' and commit the generated file.",
    )
    process.exit(1)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2)
  if (args[0] === '--shipped') {
    if (!args[1]) {
      console.error('::error::--shipped needs the base commit')
      process.exit(1)
    }
    printShipped(args[1])
  } else {
    requireAuthRelease(args)
  }
}
