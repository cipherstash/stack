import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * `wasm:wasi-check` greps `cargo tree` output for crates that must never link
 * into a WASI guest. CI sets `CARGO_TERM_COLOR=always`, and cargo then wraps
 * each line's tree prefix in ANSI colour codes. The grep anchors on that
 * prefix, so with colour on it can never match: the gate passed with
 * `wasm-bindgen` added to stack-kms in a deliberate-break run on 2 October
 * 2026, while the same break failed it locally, where output is plain.
 */

const miseToml = readFileSync(join(REPO_ROOT, 'mise.toml'), 'utf8')

function taskRun(name) {
  const start = miseToml.indexOf(`[tasks."${name}"]`)
  expect(start, `${name} task`).toBeGreaterThan(-1)
  const open = miseToml.indexOf('run = """', start)
  const close = miseToml.indexOf('"""', open + 'run = """'.length)
  return miseToml.slice(open, close)
}

const run = taskRun('wasm:wasi-check')

describe('wasm:wasi-check dependency gate', () => {
  it('asks cargo tree for uncoloured output', () => {
    const calls = run.match(/^(?!\s*#).*cargo tree[^\n]*/gm) ?? []
    expect(calls.length).toBeGreaterThan(0)
    for (const call of calls) expect(call).toContain('--color never')
  })

  it('its patterns match a forbidden crate in a plain tree, and not in a coloured one', () => {
    const patterns = [...run.matchAll(/grep -Eq '([^']+)'/g)].map(
      ([, pattern]) => new RegExp(pattern, 'm'),
    )
    expect(patterns.length).toBe(2)
    const plain = 'stack-kms v0.1.0\n├── wasm-bindgen v0.2.100\n'
    const coloured =
      'stack-kms v0.1.0\n\u001b[2m├── \u001b[0mwasm-bindgen v0.2.100\n'
    expect(patterns[0].test(plain)).toBe(true)
    // Documents why `--color never` is load-bearing.
    expect(patterns[0].test(coloured)).toBe(false)
  })
})
