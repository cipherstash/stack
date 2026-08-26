/**
 * A build that copies `skills/` must declare `skills/` as an input.
 *
 * `packages/cli` and `packages/wizard` both `cpSync('../../skills',
 * 'dist/skills')` — they consume a directory outside their own package, which
 * turbo's `$TURBO_DEFAULT$` does not cover. On its own that only meant a stale
 * cache entry stayed valid; once `build` declared `outputs: ["dist/**"]`, a
 * cache hit began actively RESTORING the previous `dist/skills` over the tree.
 *
 * `skills/` ships inside the `stash` and `@cipherstash/wizard` tarballs and
 * `stash init` copies it into customer repos, so the failure mode is publishing
 * guidance that was edited but never rebuilt — invisible, because the build is
 * green and the source file on disk is correct.
 *
 * Verified by hand at the time of writing: edit a `SKILL.md`, run
 * `turbo run build --filter=stash`, observe FULL TURBO and a `dist/skills` copy
 * without the edit. This pins the fix so it cannot silently come undone.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { readJsonc } from './lib/read-jsonc.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/** Packages whose tsup config copies the repo-root `skills/` into `dist/`. */
function packagesCopyingSkills() {
  const pkgsDir = join(REPO_ROOT, 'packages')
  const found = []
  for (const entry of readdirSync(pkgsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const tsup = join(pkgsDir, entry.name, 'tsup.config.ts')
    const pkgJson = join(pkgsDir, entry.name, 'package.json')
    if (!existsSync(tsup) || !existsSync(pkgJson)) continue
    if (
      !/cpSync\(\s*['"]\.\.\/\.\.\/skills['"]/.test(readFileSync(tsup, 'utf8'))
    )
      continue
    found.push(JSON.parse(readFileSync(pkgJson, 'utf8')).name)
  }
  return found
}

describe('turbo build inputs cover the skills directory', () => {
  const turbo = readJsonc(join(REPO_ROOT, 'turbo.json'))
  const copiers = packagesCopyingSkills()

  it('finds the packages that copy skills into their bundle', () => {
    // If this drops to zero the rest of the suite silently passes, so pin it.
    expect(copiers).toEqual(
      expect.arrayContaining(['stash', '@cipherstash/wizard']),
    )
  })

  it.each(packagesCopyingSkills().map((name) => [name]))(
    '%s#build declares skills as an input',
    (name) => {
      const task = turbo.tasks[`${name}#build`]

      expect(
        task,
        `turbo.json has no "${name}#build" task, so it inherits the generic ` +
          '`build` inputs, which do not include the repo-root skills/ directory',
      ).toBeDefined()

      const inputs = task.inputs ?? []
      expect(
        inputs.some((i) => i.includes('skills')),
        `"${name}#build".inputs must name the repo-root skills/ directory ` +
          '(e.g. "$TURBO_ROOT$/skills/**") or a skills-only edit will not ' +
          'invalidate the build, and `outputs: ["dist/**"]` will restore a stale copy',
      ).toBe(true)
    },
  )

  it('keeps the generic build outputs on the overrides', () => {
    // An override replaces the generic task wholesale — dropping `outputs`
    // would stop the cache restoring dist at all for these two packages.
    for (const name of copiers) {
      expect(turbo.tasks[`${name}#build`].outputs).toEqual(['dist/**'])
    }
  })
})
