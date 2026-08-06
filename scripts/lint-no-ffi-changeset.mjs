/**
 * Fail if any pending changeset names one of the seven `@cipherstash/protect-ffi`
 * packages.
 *
 * TEMPORARY. Delete this script, its self-test, its fixtures, and its
 * `lint:ffi-changeset` entry in the phase-4 cutover PR, at the same moment npm
 * trusted publishing is repointed from `cipherstash/protectjs-ffi` to
 * `cipherstash/stack`. In the same PR, `git mv` every
 * `.changeset/*.md.deferred` to `*.md` — see "Where a deferred changeset
 * waits" below.
 *
 * ## Why this exists rather than the changesets `ignore` list
 *
 * The absorption plan specified `ignore` as the publication guard. Changesets
 * rejects that configuration outright:
 *
 *     The package "@cipherstash/stack" depends on the skipped package
 *     "@cipherstash/protect-ffi", but "@cipherstash/stack" is not being
 *     skipped. Please add "@cipherstash/stack" to the `ignore` option.
 *
 * An ignored package's dependents must themselves be ignored, and all three
 * consumers now depend on the wrapper at `workspace:*`. Honouring that would
 * mean ignoring `@cipherstash/stack`, `stack-drizzle` and `stack-supabase` —
 * and, through the Stack fixed group, `stash`, `stack-prisma` and `wizard`
 * with them. That is a total release freeze, which the plan considered and
 * rejected for exactly the right reason: this repo releases actively and a
 * freeze of unknown duration is a real operational cost.
 *
 * ## What actually guards the window
 *
 * Two things, and neither is configuration:
 *
 * 1. All seven packages are already on npm at 0.31.0 — the same version the
 *    workspace carries. `changeset publish` publishes only versions absent
 *    from the registry, so with no changeset naming them, a release is a
 *    no-op for all seven no matter how often `main` publishes.
 * 2. This check, which stops the one thing that would change that.
 *
 * The hazard is narrow and specific: a changeset naming any FFI package makes
 * `changeset version` bump all seven to 0.32.0 (they share a fixed group), and
 * the next release then tries to publish seven packages whose npm trusted
 * publisher still names `cipherstash/protectjs-ffi`. That is a failed or
 * misattributed publish of the encryption core.
 *
 * This is *not* a rule against changing protect-ffi. Rust and TypeScript
 * changes are fine and land normally; the constraint is only that their
 * changeset waits for the cutover PR.
 *
 * ## Where a deferred changeset waits
 *
 * `.changeset/<name>.md.deferred`. Write the changeset now, under that
 * extension, and the cutover PR is a `git mv` instead of an act of memory —
 * which matters most for the phase-2 laziness change and
 * `assertNativeBindingAvailable()`, already parked as
 * `protect-ffi-lazy-load.md.deferred`. Reconstructing that prose from the git
 * log months later is how a user-visible behaviour change ships with an empty
 * changelog.
 *
 * The suffix is load-bearing, and it is `.md.deferred` rather than
 * `.deferred.md` for a reason: `@changesets/read` selects changesets with
 * `!file.startsWith('.') && file.endsWith('.md') && !/^README\.md$/i`, and the
 * loop below filters on `.endsWith('.md')` too. A name ending in `.md`
 * publishes; a name ending in `.deferred` is invisible to both. Nothing else
 * in changesets touches it either — `getOldChangesets` only descends into
 * DIRECTORIES, `removeEmptyFolders` swallows the `ENOTDIR` a file raises, and
 * `applyReleasePlan` deletes strictly `${changeset.id}.md` for ids in the
 * release plan. Verified against the installed 2.31.0, and by
 * `changeset status` reporting no FFI package with the file in place.
 *
 * The self-test pins all of this: that a parked file exists, that it names a
 * guarded package, and that its name would NOT be read as a changeset.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

const REPO_ROOT = resolve(import.meta.dirname, '..')

const GUARDED = new Set([
  '@cipherstash/protect-ffi',
  '@cipherstash/protect-ffi-darwin-x64',
  '@cipherstash/protect-ffi-darwin-arm64',
  '@cipherstash/protect-ffi-win32-x64-msvc',
  '@cipherstash/protect-ffi-linux-x64-gnu',
  '@cipherstash/protect-ffi-linux-arm64-gnu',
  '@cipherstash/protect-ffi-linux-x64-musl',
])

const changesetDir = process.argv[2]
  ? resolve(process.argv[2])
  : join(REPO_ROOT, '.changeset')

/**
 * Pull the package names out of a changeset's frontmatter.
 *
 * A changeset is `---\n'pkg': minor\n---\n\nprose`. Only the first fenced
 * block counts: prose below it may quote a package name in a sentence, and
 * `--- ` rules inside markdown would otherwise reopen the block.
 */
function packagesIn(source) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(source)
  if (!match) return []
  return match[1]
    .split(/\r?\n/)
    .map((line) => /^\s*['"]?(@?[^'":]+?)['"]?\s*:/.exec(line))
    .filter(Boolean)
    .map((m) => m[1].trim())
}

const offenders = []
for (const entry of readdirSync(changesetDir)) {
  if (!entry.endsWith('.md') || entry === 'README.md') continue
  const named = packagesIn(readFileSync(join(changesetDir, entry), 'utf8'))
  const guarded = named.filter((name) => GUARDED.has(name))
  if (guarded.length) offenders.push({ file: entry, packages: guarded })
}

if (offenders.length === 0) {
  console.log('No pending changeset names a protect-ffi package.')
  process.exit(0)
}

console.error(
  '\nA pending changeset names a @cipherstash/protect-ffi package:\n',
)
for (const { file, packages } of offenders) {
  // Relative to the repo root, not a literal `.changeset/` — the directory is
  // overridable by argv for the self-tests, and a hardcoded prefix prints a
  // path that does not exist whenever it is.
  console.error(`  ${relative(REPO_ROOT, join(changesetDir, file))}`)
  for (const name of packages) console.error(`      ${name}`)
}
console.error(
  '\nThese seven packages live in this repo but are still PUBLISHED from\n' +
    'cipherstash/protectjs-ffi — npm trusted publishing has not been\n' +
    'repointed yet. A changeset naming any one of them bumps all seven to\n' +
    '0.32.0 through their fixed group, and the next release then attempts a\n' +
    'publish npm will reject or misattribute.\n\n' +
    'Change protect-ffi freely — only its changeset has to wait, and it has\n' +
    'somewhere to wait. Rename the file to end in `.md.deferred`:\n\n' +
    '    git mv .changeset/<name>.md .changeset/<name>.md.deferred\n\n' +
    'Changesets does not read that extension and neither does this check, so\n' +
    'the prose is written now and the cutover PR — the one that repoints\n' +
    'trusted publishing and deletes this script — renames it back.\n',
)
process.exit(1)
