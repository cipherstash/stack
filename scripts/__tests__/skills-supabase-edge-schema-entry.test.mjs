import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { packageReadmePathspecs } from './lib/package-readmes.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * A schema authored from `@cipherstash/stack/wasm-inline` cannot be handed to
 * `encryptedSupabase` from `@cipherstash/stack-supabase/wasm-inline`.
 *
 * `@cipherstash/stack/wasm-inline` is a separate tsup dts bundle. It
 * re-declares its own `EncryptedV3Column` / `EncryptedTextSearchColumn`
 * classes, each carrying a `private readonly columnName`, and TypeScript
 * compares classes with private fields NOMINALLY. The adapter types its
 * `schemas` option as `Record<string, AnyV3Table>` imported from
 * `@cipherstash/stack/eql/v3` (`packages/stack-supabase/src/schema-builder.ts`),
 * so pairing the two entries is a hard `tsc --strict` error:
 *
 *   error TS2322: Type 'EncryptedTable<...>' is not assignable to type 'AnyV3Table'.
 *     ... Types have separate declarations of a private property 'columnName'.
 *
 * The rule is therefore NOT "edge project, edge entry, everywhere". It is:
 * author the schema against the entry whose CLIENT TYPE consumes it. The raw
 * `Encryption` client from `wasm-inline` consumes `wasm-inline` tables;
 * `encryptedSupabase` consumes `eql/v3` tables on BOTH its entries, WASM engine
 * or not.
 *
 * Nothing catches the pairing for us:
 *
 * - Nothing type-checks a SKILL.md or a README, and these are shipped text —
 *   `skills/` rides inside the `stash` npm tarball and `stash init` copies it
 *   into the customer's own repository, where their coding agent reads it as
 *   instruction. The drift lands in someone else's build, not in ours.
 * - Runtime is unaffected, which is why it drifted silently in the first
 *   place: `packages/stack-supabase/src/column-map.ts` deliberately probes for
 *   v3 columns STRUCTURALLY rather than with `instanceof`, precisely because
 *   tsup emits the class twice. Copy-pasting the bad snippet produces working
 *   code that will not compile.
 * - `e2e/wasm/deno.json` runs `deno test --no-check`, so the repo's own edge
 *   e2e would not report it either.
 */

/** Modules and names that must not co-occur inside one TypeScript block. */
const ADAPTER_MODULE = '@cipherstash/stack-supabase/wasm-inline'
const ADAPTER_NAMES = ['encryptedSupabase', 'encryptedSupabaseV3']
const SCHEMA_MODULE = '@cipherstash/stack/wasm-inline'
const SCHEMA_NAMES = ['encryptedTable', 'types']

/**
 * Files whose contents are SHIPPED — published to npm, copied into a user's
 * repo, or written there by `stash init`. Deliberately not the whole tree:
 * CHANGELOGs and `docs/**` are historical records, and rewriting history to
 * appease a lint is worse than the drift it prevents.
 */
// `:(glob)` magic so `*` stops at a path separator — without it git's default
// wildmatch crosses `/` and sweeps in files a level deeper.
const SHIPPED_GLOBS = [
  ':(glob)skills/*/SKILL.md',
  // Derived, not written down: two package roots sit deeper than one level and
  // `:(glob)` does not cross `/`. See `lib/package-readmes.mjs`.
  ...packageReadmePathspecs(),
  'README.md',
  'AGENTS.md',
]

/** Tracked files matching the shipped globs, via git so it honours .gitignore. */
function shippedFiles() {
  const out = execFileSync('git', ['ls-files', '-z', ...SHIPPED_GLOBS], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
  return out.split('\0').filter(Boolean)
}

/**
 * Fenced TypeScript blocks, as `{ line, body }`.
 *
 * Per BLOCK, not per file: a document may legitimately import
 * `@cipherstash/stack/wasm-inline` in one snippet (the raw edge client, which
 * really does want its own tables) and construct `encryptedSupabase` in
 * another. Only the two appearing in the same snippet is the defect.
 */
function typescriptBlocks(body) {
  const blocks = []
  const fence = /^```(ts|typescript)[^\n]*\n([\s\S]*?)^```/gm
  for (const match of body.matchAll(fence)) {
    blocks.push({
      line: body.slice(0, match.index).split('\n').length,
      body: match[2],
    })
  }
  return blocks
}

/** Named imports in one block, as `{ module, names }`. */
function namedImports(block) {
  const imports = []
  const stmt = /import\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g
  for (const match of block.matchAll(stmt)) {
    imports.push({
      module: match[2],
      names: match[1]
        .split(',')
        .map((name) =>
          name
            .trim()
            .split(/\s+as\s+/)[0]
            .trim(),
        )
        .filter(Boolean),
    })
  }
  return imports
}

/** Does this block import any of `names` from `module`? */
function importsAny(imports, module, names) {
  return imports.some(
    (imported) =>
      imported.module === module &&
      imported.names.some((name) => names.includes(name)),
  )
}

describe('supabase edge snippets author schemas from @cipherstash/stack/eql/v3', () => {
  const files = shippedFiles()

  it('finds the shipped file set (guards against a silently-empty glob)', () => {
    expect(files.length).toBeGreaterThan(5)
    expect(files).toContain('skills/stash-supabase/SKILL.md')
    expect(files).toContain('skills/stash-managed-platforms/SKILL.md')
    expect(files).toContain('skills/stash-edge/SKILL.md')
    expect(files).toContain('packages/stack-supabase/README.md')
  })

  it.each(files)('%s', (file) => {
    const body = readFileSync(resolve(REPO_ROOT, file), 'utf8')
    const offenders = typescriptBlocks(body)
      .filter((block) => {
        const imports = namedImports(block.body)
        return (
          importsAny(imports, ADAPTER_MODULE, ADAPTER_NAMES) &&
          importsAny(imports, SCHEMA_MODULE, SCHEMA_NAMES)
        )
      })
      .map((block) => `${file}:${block.line}`)

    expect(
      offenders,
      `${offenders.join(', ')} pairs \`encryptedSupabase\` from ${ADAPTER_MODULE} with a schema ` +
        `authored from ${SCHEMA_MODULE}. That does not compile: the adapter's \`schemas\` option is ` +
        "typed from `@cipherstash/stack/eql/v3`, and the two entries' column classes carry private " +
        'fields TypeScript compares nominally (TS2322, "separate declarations of a private property ' +
        "'columnName'\"). Import `encryptedTable` and `types` from `@cipherstash/stack/eql/v3` — the " +
        'engine stays WASM either way.',
    ).toEqual([])
  })
})
