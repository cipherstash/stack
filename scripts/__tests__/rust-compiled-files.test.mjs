import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  compiledCrateFiles,
  includes,
  moduleDeclarations,
  stripComments,
} from './lib/rust-compiled-files.mjs'

/**
 * `compiledCrateFiles` decides which files of a path dependency the FFI cache
 * keys and the workflow filters may leave out. Against the real tree it is
 * checked by ffi-binding-action.test.mjs (and was checked once by hand against
 * cargo's own dep-info for eql-bindings: the same 26 source files). These
 * cases pin the forms that tree does not happen to contain today.
 */

const root = mkdtempSync(join(tmpdir(), 'rust-compiled-files-'))
afterAll(() => rmSync(root, { recursive: true, force: true }))

function crate(name, files) {
  for (const [path, text] of Object.entries(files)) {
    const full = join(root, name, path)
    mkdirSync(dirname(full), { recursive: true })
    writeFileSync(full, text)
  }
  return name
}

describe('compiledCrateFiles', () => {
  const dir = crate('gated', {
    'Cargo.toml': '[package]\nname = "gated"\n',
    'src/lib.rs': [
      'pub mod always;',
      '#[cfg(feature = "extra")]',
      'pub mod extra;',
      '#[cfg(test)]',
      'mod tests;',
      '#[path = "elsewhere/renamed.rs"]',
      'mod moved;',
      'pub const SQL: &str = include_str!("../sql/bundle.sql");',
    ].join('\n'),
    'src/always.rs': 'mod child;\n',
    'src/always/child.rs': '',
    'src/extra/mod.rs': 'mod deeper;\n',
    'src/extra/deeper.rs': '',
    'src/tests.rs': '',
    'src/elsewhere/renamed.rs': '',
    'sql/bundle.sql': '',
    'README.md': '',
    'tests/integration.rs': '',
  })

  it('drops a module gated on a feature that is off', () => {
    const { files, unresolved } = compiledCrateFiles(root, dir, new Set())
    expect(unresolved).toEqual([])
    expect(files).toEqual(
      [
        'Cargo.toml',
        'sql/bundle.sql',
        'src/always.rs',
        'src/always/child.rs',
        'src/elsewhere/renamed.rs',
        'src/lib.rs',
        'src/tests.rs',
      ].map((file) => `${dir}/${file}`),
    )
  })

  it('follows it, and its children, when the feature is on', () => {
    const { files } = compiledCrateFiles(root, dir, new Set(['extra']))
    expect(files).toContain(`${dir}/src/extra/mod.rs`)
    expect(files).toContain(`${dir}/src/extra/deeper.rs`)
  })

  it('reports what it cannot follow instead of skipping it', () => {
    const broken = crate('broken', {
      'Cargo.toml': '[package]\nname = "broken"\n',
      'src/lib.rs': [
        'mod missing;',
        'const X: &str = include_str!(concat!(env!("OUT_DIR"), "/x"));',
        'mod inline { mod nested; }',
      ].join('\n'),
    })
    const { unresolved } = compiledCrateFiles(root, broken, new Set())
    expect(unresolved).toHaveLength(3)
  })

  it('reads `[lib] path`', () => {
    const custom = crate('custom', {
      'Cargo.toml':
        '[package]\nname = "custom"\n\n[lib]\npath = "lib/root.rs"\n',
      'lib/root.rs': 'mod a;\n',
      'lib/a.rs': '',
    })
    expect(compiledCrateFiles(root, custom, new Set()).files).toEqual([
      `${custom}/Cargo.toml`,
      `${custom}/lib/a.rs`,
      `${custom}/lib/root.rs`,
    ])
  })
})

describe('the source readers', () => {
  it('ignores declarations in comments and keeps strings intact', () => {
    const text = [
      '// mod commented;',
      '/* mod blocked; /* nested */ still; */',
      'const S: &str = "// not a comment";',
      "const C: char = '\"';",
      'const R: &str = r#"// "quoted" "#;',
      'mod real;',
    ].join('\n')
    const stripped = stripComments(text)
    expect(stripped).toContain('"// not a comment"')
    expect(stripped).toContain('r#"// "quoted" "#')
    expect(moduleDeclarations(text).map((decl) => decl.name)).toEqual(['real'])
  })

  it('reads only the attributes written directly above a declaration', () => {
    const decls = moduleDeclarations(
      [
        '#[cfg(feature = "a")]',
        'fn f() {}',
        'mod plain;',
        '#[doc(hidden)]',
        '#[cfg(feature = "b")]',
        'pub(crate) mod gated;',
        '#[cfg(not(feature = "c"))]',
        'mod negated;',
      ].join('\n'),
    )
    expect(decls.map(({ name, feature }) => ({ name, feature }))).toEqual([
      { name: 'plain', feature: undefined },
      { name: 'gated', feature: 'b' },
      { name: 'negated', feature: undefined },
    ])
  })

  it('reads include macro arguments only when they are plain literals', () => {
    expect(
      includes(
        'include_str!("a.sql"); include_bytes!( "b.bin" ); include!(x);',
      ),
    ).toEqual([
      { macro: 'include_str', literal: 'a.sql' },
      { macro: 'include_bytes', literal: 'b.bin' },
      { macro: 'include', literal: undefined },
    ])
  })
})
