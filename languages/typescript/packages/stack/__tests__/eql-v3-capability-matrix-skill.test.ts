import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { types } from '@/eql/v3'

/**
 * The capability matrix in `skills/stash-encryption/SKILL.md` must stay true
 * to the `types` namespace (#892).
 *
 * The matrix exists because picking the wrong factory is silent at authoring
 * time — no type error, no runtime warning, just a predicate that never runs.
 * A table documenting that, which has itself drifted, is worse than no table:
 * it converts a discoverable gap into confident wrong guidance, and it ships
 * inside the `stash` tarball into customers' repos.
 *
 * Deriving the matrix at build time was the alternative. This repo has no
 * markdown codegen and the skills are hand-authored prose around their tables,
 * so a generator would own a fragment of a file humans edit. Pinning is the
 * pattern already used for skill content (`skill-supabase-apply.test.ts`), and
 * it fails in the same place a generator would: the moment source and prose
 * disagree.
 *
 * What is checked is the mechanical half — every factory present, mapped to
 * the domain the factory actually builds, with the index kinds it actually
 * emits. The prose around it is a human's job.
 */

const SKILL = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../../skills/stash-encryption/SKILL.md',
)

/** Only the matrix, so an example elsewhere in the file cannot satisfy a row. */
function matrixRows(): string[] {
  const body = readFileSync(SKILL, 'utf-8')
  const start = body.indexOf('#### The capability matrix')
  expect(start, 'the capability matrix heading is missing').toBeGreaterThan(-1)
  const end = body.indexOf('That is the whole surface', start)
  expect(end, 'the matrix closing paragraph is missing').toBeGreaterThan(start)
  return body
    .slice(start, end)
    .split('\n')
    .filter((line) => line.trimStart().startsWith('| `types.'))
}

/** The index kinds a factory emits, e.g. `['ope', 'unique']`. */
function indexKindsFor(name: keyof typeof types): string[] {
  const factory = types[name] as (column: string) => {
    build: () => { indexes?: Record<string, unknown> }
  }
  return Object.keys(factory('__probe__').build().indexes ?? {}).sort()
}

function eqlTypeFor(name: keyof typeof types): string {
  const factory = types[name] as (column: string) => {
    getEqlType: () => string
  }
  return factory('__probe__').getEqlType()
}

const FACTORY_NAMES = Object.keys(types) as Array<keyof typeof types>

/**
 * The extractor each index kind is indexed through — the "What to index"
 * column. `ste_vec` is the one that is not a scalar extractor.
 */
const EXTRACTOR_FOR_INDEX: Record<string, string> = {
  unique: 'eq_term',
  ope: 'ord_term',
  ore: 'ord_term_ore',
  match: 'match_term',
  ste_vec: 'to_ste_vec_query',
}

/**
 * Matched in its backticked form, because `ord_term` is a substring of
 * `ord_term_ore` — a bare substring test reads an ORE row as also naming the
 * OPE extractor and the negative assertions below become unsatisfiable.
 */
const backticked = (extractor: string) => `\`${extractor}\``

describe('the stash-encryption capability matrix', () => {
  it('has exactly one row per factory, and no rows for anything else', () => {
    const rows = matrixRows()
    const listed = rows.map((row) => {
      const match = /^\|\s*`types\.(\w+)\(/.exec(row.trimStart())
      expect(match, `could not read a factory name from row: ${row}`).not.toBe(
        null,
      )
      return (match as RegExpExecArray)[1]
    })
    expect([...listed].sort()).toEqual([...FACTORY_NAMES].sort())
    // No duplicate rows: a factory documented twice can be documented two
    // different ways.
    expect(new Set(listed).size).toBe(listed.length)
  })

  it('names the domain each factory actually builds', () => {
    const rows = matrixRows()
    for (const name of FACTORY_NAMES) {
      const row = rows.find((candidate) =>
        candidate.trimStart().startsWith(`| \`types.${name}(`),
      )
      expect(row, `no matrix row for types.${name}`).toBeDefined()
      expect(
        row,
        `types.${name} builds ${eqlTypeFor(name)}, which its matrix row does not name`,
      ).toContain(`\`${eqlTypeFor(name)}\``)
    }
  })

  /**
   * The trap the issue was filed about: `types.Double` mints no ORE blocks and
   * answers no predicate, but its name suggests otherwise. Every storage-only
   * factory must say so in its own row.
   */
  it('marks every storage-only factory as answering nothing', () => {
    const rows = matrixRows()
    for (const name of FACTORY_NAMES) {
      if (indexKindsFor(name).length > 0) continue
      const row = rows.find((candidate) =>
        candidate.trimStart().startsWith(`| \`types.${name}(`),
      )
      expect(
        row,
        `types.${name} emits no index terms, so its row must say storage only`,
      ).toContain('storage only')
    }
  })

  /**
   * The "What to index" column must name the extractor the column's terms are
   * actually reachable through — indexing an extractor a domain has no
   * overload for builds an index that never engages.
   */
  it('names the right extractor for every queryable factory', () => {
    const rows = matrixRows()
    for (const name of FACTORY_NAMES) {
      const kinds = indexKindsFor(name)
      if (kinds.length === 0) continue
      const row = rows.find((candidate) =>
        candidate.trimStart().startsWith(`| \`types.${name}(`),
      )
      // Rows that defer to a sibling ("as `IntegerOrd`") repeat the ORE
      // extractor but not the shared predicate list, so only assert the
      // extractors, which every row carries in full.
      for (const kind of kinds) {
        expect(
          row,
          `types.${name} emits a '${kind}' index, so its row must name ${EXTRACTOR_FOR_INDEX[kind]}`,
        ).toContain(backticked(EXTRACTOR_FOR_INDEX[kind]))
      }
      // ...and must NOT name an extractor the domain has no overload for. The
      // numeric `_ord` domains are the live case: they answer `=` through the
      // injective ordering term and define no `eq_term`.
      for (const [kind, extractor] of Object.entries(EXTRACTOR_FOR_INDEX)) {
        if (kinds.includes(kind)) continue
        expect(
          row,
          `types.${name} emits no '${kind}' index, so its row must not name ${extractor}`,
        ).not.toContain(backticked(extractor))
      }
    }
  })

  /**
   * Every ORE factory is unusable where the operator class could not be
   * created — the bundle poisons those domains with an always-raising CHECK,
   * so a write fails rather than an index quietly not engaging. The matrix
   * must not soften that into "usable but unindexable".
   */
  it('marks every ORE factory as unusable on a database without the opclass', () => {
    const rows = matrixRows()
    for (const name of FACTORY_NAMES) {
      if (!indexKindsFor(name).includes('ore')) continue
      const row = rows.find((candidate) =>
        candidate.trimStart().startsWith(`| \`types.${name}(`),
      )
      expect(row, `types.${name} is ORE-backed; its row must say so`).toContain(
        'privileged install only',
      )
      expect(row).toContain('unusable')
    }
  })
})
