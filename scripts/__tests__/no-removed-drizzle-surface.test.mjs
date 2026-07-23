import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

/**
 * The `@cipherstash/stack-drizzle` names removed when EQL v2 went away and
 * `./v3` collapsed into the package root. Nothing type-checks a README, a
 * SKILL.md, or a template literal, so these three drifted silently before —
 * and `skills/` ships inside the `stash` tarball, which means the drift lands
 * in a customer's repo rather than in CI.
 */
const REMOVED = [
  '@cipherstash/stack-drizzle/v3',
  'extractEncryptionSchemaV3',
  'createEncryptionOperatorsV3',
]

/**
 * Files whose contents are SHIPPED — published to npm, copied into a user's
 * repo, or written there by `stash init`. Deliberately not the whole tree:
 * CHANGELOGs and `docs/superpowers/specs/**` are historical records that
 * SHOULD still name the old surface, and rewriting history to appease a lint
 * is worse than the drift it prevents.
 */
// `:(glob)` magic so `*` stops at a path separator — without it git's default
// wildmatch crosses `/` and `lib/*.ts` sweeps in `lib/__tests__/*.test.ts`.
const SHIPPED_GLOBS = [
  ':(glob)skills/*/SKILL.md',
  ':(glob)packages/*/README.md',
  'README.md',
  'AGENTS.md',
  // `stash init` writes these strings into the user's project as real source.
  'packages/cli/src/commands/init/utils.ts',
  ':(glob)packages/cli/src/commands/init/lib/*.ts',
  ':(glob)packages/cli/src/commands/init/doctrine/*.md',
]

/** Tracked files matching the shipped globs, via git so it honours .gitignore. */
function shippedFiles() {
  const out = execFileSync('git', ['ls-files', '-z', ...SHIPPED_GLOBS], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
  return out.split('\0').filter(Boolean)
}

describe('removed stack-drizzle surface is absent from shipped files', () => {
  const files = shippedFiles()

  it('finds the shipped file set (guards against a silently-empty glob)', () => {
    expect(files.length).toBeGreaterThan(5)
    expect(files).toContain('skills/stash-drizzle/SKILL.md')
    expect(files).toContain('packages/stack/README.md')
  })

  it.each(files)('%s', (file) => {
    const body = readFileSync(resolve(REPO_ROOT, file), 'utf8')
    const found = REMOVED.filter((name) => body.includes(name))
    expect(
      found,
      `${file} names removed @cipherstash/stack-drizzle exports: ${found.join(', ')}. ` +
        'The `./v3` subpath collapsed into the package root and the *V3 suffixes were dropped.',
    ).toEqual([])
  })
})
