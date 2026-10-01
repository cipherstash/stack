/**
 * Proves the TypeScript code union and the Rust codes are the same set.
 *
 * `ProtectErrorCode` was an independently maintained list until #146: Rust
 * emitted nothing, and `src/errors.ts` reconstructed a code by matching the
 * message against ~14 prefixes and substrings. Rust now names the code on the
 * variant, which leaves exactly one way for this to go wrong — the two lists
 * drifting apart — and it is a silent way, because a code TypeScript does not
 * declare still arrives at runtime and still fails `isProtectErrorCode`.
 *
 * So this reads the Rust and compares. It is the cheap version of generating
 * the union (the shape `scripts/sync-eql-v3-types.sh` uses for the EQL v3
 * types); worth revisiting if the set starts changing often.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { PROTECT_ERROR_CODES } from './errors.js'

// Vitest resolves cwd to the directory holding vitest.config.ts. `import.meta`
// is unavailable here: tsconfig emits CommonJS, and tsc rejects it (TS1470).
const repoRoot = process.cwd()
const read = (relative: string) =>
  readFileSync(join(repoRoot, relative), 'utf8')

const manifest = JSON.parse(read('package.json'))
const libRs = read('crates/protect-ffi/src/lib.rs')

/**
 * `UNKNOWN` is the one code Rust never emits — it is the JS-side name for "this
 * error had no code", which arrives as an absent field.
 */
const JS_ONLY_CODES = new Set(['UNKNOWN'])

// Anchored to the start of a line so the enum's own doc comment, which spells
// `#[diagnostic(code(..))]` in prose, is not mistaken for an attribute.
const CODE_ATTRIBUTE = /^\s*#\[diagnostic\(code\("([A-Z0-9_]+)"\)\)\]$/gm
const ANY_CODE_ATTRIBUTE = /^\s*#\[diagnostic\(code\(/gm

const rustCodes = new Set(
  [...libRs.matchAll(CODE_ATTRIBUTE)].map((match) => match[1]),
)

describe('error codes', () => {
  it('reads the files it means to read', () => {
    // Every assertion below is on file contents resolved from cwd. A wrong cwd
    // would make them vacuous rather than failing, so pin it.
    expect(manifest.name).toBe('@cipherstash/protect-ffi')
    expect(rustCodes.size).toBeGreaterThan(0)
  })

  it('spells every Rust code as a string literal', () => {
    // miette also accepts `#[diagnostic(code(some::path))]`, which the regex
    // above would not see — and a code this test cannot see is a code it
    // cannot check. Counting the attributes catches that.
    const attributes = [...libRs.matchAll(ANY_CODE_ATTRIBUTE)]
    const parsed = [...libRs.matchAll(CODE_ATTRIBUTE)]

    expect(attributes.length).toBe(parsed.length)
  })

  it('declares every code Rust can emit', () => {
    const declared = new Set<string>(PROTECT_ERROR_CODES)
    const undeclared = [...rustCodes].filter((code) => !declared.has(code))

    expect(undeclared).toEqual([])
  })

  it('declares no code Rust cannot emit', () => {
    const orphans = PROTECT_ERROR_CODES.filter(
      (code) => !rustCodes.has(code) && !JS_ONLY_CODES.has(code),
    )

    expect(orphans).toEqual([])
  })

  it('routes the config codes by upstream variant, not by message', () => {
    // These three are the ones that used to be recovered from
    // cipherstash-config's wording (`' requires plaintext_type: json'`), which
    // nothing here owned. They are decided in `From<ConfigError> for Error`
    // now, so a rename upstream is a compile error rather than a silent
    // downgrade to UNKNOWN.
    const router = /impl From<ConfigError> for Error \{[\s\S]*?\n\}/.exec(libRs)
    expect(router, 'the ConfigError router should exist').not.toBeNull()

    for (const variant of [
      'ConfigError::SteVecRequiresJson',
      'ConfigError::MatchRequiresText',
      'ConfigError::UnsupportedVersion',
    ]) {
      expect(router?.[0]).toContain(variant)
    }

    for (const code of [
      'STE_VEC_REQUIRES_JSON_CAST_AS',
      'MATCH_REQUIRES_TEXT',
      'UNSUPPORTED_CONFIG_VERSION',
    ]) {
      expect(rustCodes).toContain(code)
    }
  })
})

/**
 * The wasm bundle declares its error-helper exports in one place and produces
 * them in another, and neither knows about the other.
 *
 * `crates/protect-ffi/src/wasm.rs` carries a `typescript_custom_section` whose
 * errors.js re-export block is what a consumer's TypeScript sees.
 * The runtime half is appended to wasm-pack's output by
 * `scripts/inline-wasm.mjs`, because wasm-bindgen cannot re-export arbitrary
 * JavaScript values from a custom section.
 *
 * A name in the first and not the second is a declared export that does not
 * exist at runtime — a `TypeError` in an edge function, with a green build.
 */
describe('wasm error-helper exports', () => {
  // Anchored per file rather than one loose pattern over both, for the reason
  // CODE_ATTRIBUTE above is anchored: a doc comment that quotes the statement
  // it is describing would otherwise be scraped as the statement, and the test
  // would compare prose to code. In `wasm.rs` the block starts a line; in
  // `inline-wasm.mjs` it is a single-quoted JavaScript string.
  const declared = /^export \{([^}]*)\} from "\.\/errors\.js";$/m.exec(
    read('crates/protect-ffi/src/wasm.rs'),
  )
  const emitted = /'export \{([^}]*)\} from "\.\/errors\.js";'/.exec(
    read('scripts/inline-wasm.mjs'),
  )

  /** Value exports only — a `type` specifier has no runtime counterpart. */
  const names = (block: RegExpExecArray | null) =>
    (block?.[1] ?? '')
      .split(',')
      .map((name) => name.trim())
      .filter((name) => name.length > 0 && !name.startsWith('type '))
      .sort()

  it('finds both re-export blocks', () => {
    // Without this the comparison below passes vacuously — two empty sets are
    // equal, and a regex that stopped matching would read as agreement.
    expect(names(declared).length).toBeGreaterThan(0)
    expect(names(emitted).length).toBeGreaterThan(0)
  })

  it('declares exactly the names the inline bundle re-exports', () => {
    expect(names(declared)).toEqual(names(emitted))
  })
})
