import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

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
    expect(run(fx('clean')).output).not.toMatch(/README/)
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
    const guarded = readFileSync(SCRIPT, 'utf8')
    expect(ffiGroup).toHaveLength(7)
    for (const name of ffiGroup) expect(guarded).toMatch(`'${name}'`)
  })
})
