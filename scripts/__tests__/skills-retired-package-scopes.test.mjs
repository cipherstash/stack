/**
 * A shipped skill must not name a package that no longer exists.
 *
 * `skills/*` are published artefacts: `packages/cli/tsup.config.ts` copies them
 * into the `stash` tarball and `installSkills()` copies them into a customer's
 * `.claude/skills/`. A code sample there is not compiled by anything — not by
 * `tsc`, not by Biome, not by any suite in this repo — so an import naming a
 * retired scope reads exactly like a working one until a customer pastes it and
 * gets `ERR_MODULE_NOT_FOUND`.
 *
 * THIS IS NOT HYPOTHETICAL. Prisma Next 0.17 retired the whole `@prisma-next/*`
 * scope in favour of `@prisma/orm-*`. The upgrade landed with
 * `skills/stash-prisma/SKILL.md` rewritten for the new names — and a later merge
 * reintroduced a section, written against the old surface on a branch cut before
 * the upgrade, carrying `rawSql` imported from `@prisma-next/postgres/migration`.
 * Two package names in one line, neither resolvable, in the file whose entire job
 * is telling a customer what to type. Everything was green.
 *
 * WHY THE RULE IS "SCOPE, NOT PACKAGE". `@prisma-next/*` — the scope wildcard —
 * stays allowed, because a skill sometimes has to SAY the scope is retired, and
 * `skills/stash-prisma` does exactly that. What is banned is a concrete member of
 * it, `@prisma-next/<something>`, which can only ever be an import. That keeps the
 * check sharp enough to have caught the real defect while permitting the sentence
 * that warns about it.
 *
 * The bare CLI binary `prisma-next` is untouched by any of this: `npx prisma-next
 * migrate` is still the command. Only the npm scope moved, so the pattern is
 * anchored on the leading `@`.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

const SKILLS_DIR = join(REPO_ROOT, 'skills')

/**
 * Package scopes that have been retired, with the replacement to name instead.
 *
 * Add an entry the same day a dependency renames its scope — the window this
 * guard covers is between the rename and the next reader of the skill, and
 * nothing else in the repo is watching it.
 */
const RETIRED_SCOPES = [
  {
    scope: '@prisma-next',
    replacement: '@prisma/orm-* (Prisma Next 0.17 renamed the whole scope)',
  },
]

/** Every `skills/<name>/SKILL.md`, as `{ name, path, text }`. */
function shippedSkills() {
  return readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({
      name: entry.name,
      path: join(SKILLS_DIR, entry.name, 'SKILL.md'),
    }))
    .filter(({ path }) => {
      try {
        readFileSync(path)
        return true
      } catch {
        return false
      }
    })
    .map((skill) => ({ ...skill, text: readFileSync(skill.path, 'utf8') }))
}

/**
 * Concrete members of `scope` named in `text`, with the 1-based line of each.
 *
 * The negative lookahead is what separates a package from the scope wildcard:
 * `@prisma-next/target-postgres` is a hit, `@prisma-next/*` is not.
 */
function retiredPackageReferences(text, scope) {
  const pattern = new RegExp(`${scope}/(?!\\*)[a-z0-9][a-z0-9._-]*`, 'gi')
  const hits = []
  text.split('\n').forEach((line, index) => {
    for (const match of line.matchAll(pattern)) {
      hits.push({ line: index + 1, specifier: match[0] })
    }
  })
  return hits
}

describe('shipped skills name no retired package scope', () => {
  const skills = shippedSkills()

  it('finds the skills to check', () => {
    // A zero-length scan passes every assertion below without reading a byte,
    // which is the one way this file could go quiet. `skills/` is a documented
    // part of the `stash` tarball, so a floor is safe to assert.
    expect(skills.length).toBeGreaterThanOrEqual(10)
    expect(skills.map((skill) => skill.name)).toContain('stash-prisma')
  })

  for (const { scope, replacement } of RETIRED_SCOPES) {
    it(`no skill imports from \`${scope}/\``, () => {
      const offenders = skills.flatMap(({ name, text }) =>
        retiredPackageReferences(text, scope).map(
          ({ line, specifier }) =>
            `skills/${name}/SKILL.md:${line} names \`${specifier}\` — use ${replacement}`,
        ),
      )
      expect(offenders).toEqual([])
    })
  }

  it('the scope wildcard itself stays allowed, so the retirement can be documented', () => {
    // `skills/stash-prisma` tells the reader the scope is retired, and must be
    // able to keep doing so. If the rule above ever widens to a bare scope
    // match, this fails rather than the sentence quietly disappearing.
    const prisma = skills.find((skill) => skill.name === 'stash-prisma')
    expect(prisma).toBeDefined()
    expect(prisma.text).toContain('@prisma-next/*')
    expect(retiredPackageReferences(prisma.text, '@prisma-next')).toEqual([])
  })
})
