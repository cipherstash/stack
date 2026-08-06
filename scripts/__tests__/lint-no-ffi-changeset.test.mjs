import { execFileSync } from 'node:child_process'
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-ffi-changeset.mjs',
)
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

function run(dir) {
  try {
    const stdout = execFileSync('node', dir ? [SCRIPT, dir] : [SCRIPT], {
      encoding: 'utf8',
    })
    return { exitCode: 0, output: stdout }
  } catch (err) {
    return {
      exitCode: err.status,
      output: String(err.stdout) + String(err.stderr),
    }
  }
}

const fx = (name) =>
  resolve(
    fileURLToPath(import.meta.url),
    `../fixtures/lint-no-ffi-changeset/${name}`,
  )

const tempDirs = []
afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

describe('lint-no-ffi-changeset', () => {
  it('passes against the real .changeset directory', () => {
    // The whole point of the guard: until the phase-4 cutover, no pending
    // changeset may name an FFI package. If this fails on `main`, the window
    // invariant has already been broken.
    expect(run().exitCode).toBe(0)
  })

  it('passes on changesets that name no FFI package', () => {
    expect(run(fx('clean')).exitCode).toBe(0)
  })

  it('does not parse README.md as a changeset', () => {
    // `.changeset/README.md` ships with changesets itself and is not a
    // changeset; parsing it would be a false positive waiting to happen.
    //
    // The fixture README carries guarded frontmatter deliberately. Without it
    // this assertion held whether or not the skip existed — a README with no
    // frontmatter yields no package names either way, so the test passed by
    // describing the fixture rather than the behaviour.
    const { exitCode, output } = run(fx('clean'))
    expect(exitCode).toBe(0)
    expect(output).not.toMatch(/README/)
  })

  it('fails when a changeset names the wrapper', () => {
    const { exitCode, output } = run(fx('offending'))
    expect(exitCode).toBe(1)
    expect(output).toMatch('@cipherstash/protect-ffi')
    expect(output).toMatch('brave-lion-jump.md')
  })

  it('fails when a changeset names a platform package', () => {
    // Named directly rather than via the wrapper — the fixed group means one
    // is as publishing as the other.
    expect(run(fx('offending')).output).toMatch(
      '@cipherstash/protect-ffi-linux-x64-musl',
    )
  })

  it('reports every offending file, not just the first', () => {
    const { output } = run(fx('offending'))
    expect(output).toMatch('brave-lion-jump.md')
    expect(output).toMatch('quiet-moth-wait.md')
  })

  it('catches an FFI package named on any frontmatter line, not just the first', () => {
    // The likeliest real offender by some distance: one `pnpm changeset` run
    // that selects the package you changed AND protect-ffi, which writes both
    // into a single block. Every other fixture here names exactly one package
    // on line one, so a parser that read only the first line of frontmatter
    // passed this whole suite — mutation-tested by appending `.slice(0, 1)`
    // to the frontmatter split: 10/10 still green. `darwin-arm64` appears in
    // no other fixture, so matching it proves the second line was read.
    const { exitCode, output } = run(fx('offending'))
    expect(exitCode).toBe(1)
    expect(output).toMatch('@cipherstash/protect-ffi-darwin-arm64')
    expect(output).toMatch('wise-crane-list.md')
  })

  it('parses a changeset checked out with CRLF line endings', () => {
    // `packagesIn` spells its line breaks `\r?\n` in both the frontmatter
    // regex and the split — deliberate, because a Windows checkout with
    // `core.autocrlf=true` yields CRLF, and this repo has no `.gitattributes`
    // forcing otherwise. Nothing exercised it: dropping both `\r?` left the
    // suite green, and the guard would then wave through every changeset
    // written on Windows.
    //
    // Generated rather than committed for the same reason it needs testing —
    // a CRLF fixture in git is one `autocrlf=true` commit away from being
    // silently normalised to LF, which would disarm this test without a diff.
    const dir = mkdtempSync(join(tmpdir(), 'ffi-changeset-crlf-'))
    tempDirs.push(dir)
    writeFileSync(
      join(dir, 'tidy-vole-climb.md'),
      "---\r\n'@cipherstash/stack': patch\r\n'@cipherstash/protect-ffi-linux-arm64-gnu': patch\r\n---\r\n\r\nWritten on Windows.\r\n",
    )

    const { exitCode, output } = run(dir)
    expect(exitCode).toBe(1)
    expect(output).toMatch('@cipherstash/protect-ffi-linux-arm64-gnu')
  })

  it('ignores an FFI package named only in the prose body', () => {
    // A Stack changeset describing the 0.31 adoption necessarily mentions
    // protect-ffi in its text, and may quote frontmatter to show a shape.
    // Only the first fenced block is frontmatter.
    expect(run(fx('prose-mention')).exitCode).toBe(0)
  })

  it('explains that the changeset should wait, not the change', () => {
    // The failure a reader hits is "I changed Rust and CI went red". The
    // message has to distinguish those two things or it reads as a ban on
    // touching the package.
    const { output } = run(fx('offending'))
    expect(output).toMatch(/cutover PR/)
    expect(output).toMatch(/Change protect-ffi freely/)
  })

  it('skips a parked `.md.deferred` changeset naming an FFI package', () => {
    // The window has to leave protect-ffi's changeset somewhere, or the prose
    // is reconstructed from the git log at cutover time. `.md.deferred` is
    // that parking spot, and this is the behaviour that makes it one.
    //
    // Generated rather than committed so the assertion is about the SKIP. Run
    // against the real .changeset directory it would also pass if the parked
    // file simply named nothing guarded.
    const dir = mkdtempSync(join(tmpdir(), 'ffi-changeset-deferred-'))
    tempDirs.push(dir)
    writeFileSync(
      join(dir, 'parked.md.deferred'),
      "---\n'@cipherstash/protect-ffi': minor\n---\n\nWaiting for the cutover.\n",
    )

    expect(run(dir).exitCode).toBe(0)
  })

  it('has the deferred laziness changeset already written and parked', () => {
    // Why the guard can be deleted safely at cutover: the changeset it defers
    // is not a thing someone has to remember to write, it is a `git mv`. The
    // phase-4 checklist says so; this is what stops the file being deleted,
    // emptied or renamed out from under that instruction in the meantime.
    const changesetDir = resolve(REPO_ROOT, '.changeset')
    const parked = readdirSync(changesetDir).filter((f) =>
      f.endsWith('.md.deferred'),
    )
    expect(
      parked,
      'no parked changeset in .changeset/ — the phase-2 laziness changeset must be written before the cutover, not during it',
    ).not.toHaveLength(0)

    // `@changesets/read` selects changeset files with
    //   !file.startsWith('.') && file.endsWith('.md') && !/^README\.md$/i
    // (@changesets/read/dist/changesets-read.esm.js). Reproduced rather than
    // imported — it is a transitive dependency, not a declared one — because
    // the failure worth catching is a well-meaning rename to
    // `<name>.deferred.md`, which changesets WOULD read, publishing all seven
    // FFI packages into a trusted-publishing configuration that still names
    // the old repository. Suffix order is the whole safety property.
    for (const file of parked) {
      expect(
        !file.startsWith('.') &&
          file.endsWith('.md') &&
          !/^README\.md$/i.test(file),
        `${file} would be read by changesets as a live changeset`,
      ).toBe(false)
    }

    const parkedPackages = parked.flatMap((file) =>
      [
        ...readFileSync(join(changesetDir, file), 'utf8').matchAll(
          /^\s*['"]?(@?[^'":\n]+?)['"]?\s*:\s*(?:major|minor|patch)\s*$/gm,
        ),
      ].map(([, name]) => name),
    )
    expect(
      parkedPackages,
      'a parked changeset must name @cipherstash/protect-ffi — that is the only reason to park one',
    ).toContain('@cipherstash/protect-ffi')
  })

  it('names its own removal condition in the source', () => {
    // A temporary guard with no stated expiry becomes permanent. The cutover
    // PR must be able to find this file from the plan and delete it.
    const source = readFileSync(SCRIPT, 'utf8')
    expect(source).toMatch(/TEMPORARY/)
    expect(source).toMatch(/trusted publishing/)
  })

  it('guards exactly the seven packages in the FFI fixed group', () => {
    // Drift between the guard list and the changesets fixed group would let a
    // platform package through while the group still bumps it.
    const config = JSON.parse(
      readFileSync(resolve(REPO_ROOT, '.changeset/config.json'), 'utf8'),
    )
    const ffiGroup = config.fixed.find((group) =>
      group.includes('@cipherstash/protect-ffi'),
    )
    // Both directions. Asserting only that each configured name appears in the
    // script catches a package dropped from the guard, but not one dropped
    // from the fixed group or added to only one of the two — and it is the
    // guard falling behind a NEW platform package that publishes something.
    const guardedPackages = [
      ...readFileSync(SCRIPT, 'utf8').matchAll(
        /'(@cipherstash\/protect-ffi(?:-[a-z0-9-]+)?)'/g,
      ),
    ].map(([, name]) => name)

    expect(ffiGroup).toHaveLength(7)
    expect([...new Set(guardedPackages)].sort()).toEqual([...ffiGroup].sort())
  })
})
