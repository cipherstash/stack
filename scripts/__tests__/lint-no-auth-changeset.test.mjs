import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { FROZEN_PUBLISHERS, workspaceManifests } from '../release-gate.mjs'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-auth-changeset.mjs',
)

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

// Generated rather than committed: a committed CRLF fixture is one
// `autocrlf=true` checkout away from being normalised to LF.
const tempDirs = []
function changesets(files) {
  const dir = mkdtempSync(join(tmpdir(), 'auth-changeset-'))
  tempDirs.push(dir)
  for (const [name, body] of Object.entries(files)) {
    writeFileSync(join(dir, name), body)
  }
  return dir
}
afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

describe('lint-no-auth-changeset', () => {
  it('passes against the real .changeset directory', () => {
    expect(run().exitCode).toBe(0)
  })

  it('passes on changesets that name no auth package', () => {
    const dir = changesets({
      'happy-otter-sing.md':
        "---\n'@cipherstash/stack': patch\n---\n\nA fix.\n",
    })
    expect(run(dir).exitCode).toBe(0)
  })

  it('does not parse README.md as a changeset', () => {
    // Guarded frontmatter in the README, so this passes only because of the skip.
    const dir = changesets({
      'README.md': "---\n'@cipherstash/auth': minor\n---\n\nNot a changeset.\n",
    })
    const { exitCode, output } = run(dir)
    expect(exitCode).toBe(0)
    expect(output).not.toMatch(/README/)
  })

  it('fails when a changeset names the wrapper, and reports every file', () => {
    const dir = changesets({
      'brave-lion-jump.md':
        "---\n'@cipherstash/auth': minor\n---\n\nNew API.\n",
      'quiet-moth-wait.md':
        "---\n'@cipherstash/auth-linux-x64-musl': patch\n---\n\nRebuild.\n",
    })
    const { exitCode, output } = run(dir)
    expect(exitCode).toBe(1)
    expect(output).toMatch('brave-lion-jump.md')
    expect(output).toMatch('quiet-moth-wait.md')
    expect(output).toMatch('@cipherstash/auth-linux-x64-musl')
  })

  it('catches an auth package on any frontmatter line, not just the first', () => {
    const dir = changesets({
      'wise-crane-list.md':
        "---\n'@cipherstash/stack': patch\n'@cipherstash/auth-darwin-arm64': patch\n---\n\nBoth.\n",
    })
    const { exitCode, output } = run(dir)
    expect(exitCode).toBe(1)
    expect(output).toMatch('@cipherstash/auth-darwin-arm64')
  })

  it('parses a changeset checked out with CRLF line endings', () => {
    const dir = changesets({
      'tidy-vole-climb.md':
        "---\r\n'@cipherstash/stack': patch\r\n'@cipherstash/auth-linux-arm64-gnu': patch\r\n---\r\n\r\nWritten on Windows.\r\n",
    })
    const { exitCode, output } = run(dir)
    expect(exitCode).toBe(1)
    expect(output).toMatch('@cipherstash/auth-linux-arm64-gnu')
  })

  it('ignores an auth package named only in the prose body', () => {
    const dir = changesets({
      'gentle-fox-run.md':
        "---\n'@cipherstash/stack': patch\n---\n\nUses `'@cipherstash/auth': minor` internally.\n",
    })
    expect(run(dir).exitCode).toBe(0)
  })

  it('does not guard a name that only starts with auth', () => {
    const dir = changesets({
      'odd-name.md':
        "---\n'@cipherstash/authority': patch\n---\n\nUnrelated.\n",
    })
    expect(run(dir).exitCode).toBe(0)
  })

  it('names its own removal condition in the source', () => {
    const source = readFileSync(SCRIPT, 'utf8')
    expect(source).toMatch(/TEMPORARY/)
    expect(source).toMatch(/trusted\s+publishing/)
  })

  it('guards exactly the frozen auth packages, which are the auth workspace packages', () => {
    // Three lists name the same seven packages until PR E: this guard, the
    // release gate's freeze, and the workspace. Drift between any two lets a
    // platform package through while the others still treat it as frozen.
    const guarded = [
      ...readFileSync(SCRIPT, 'utf8').matchAll(
        /'(@cipherstash\/auth(?:-[a-z0-9-]+)?)'/g,
      ),
    ].map(([, name]) => name)
    const isAuth = (name) =>
      name === '@cipherstash/auth' || name.startsWith('@cipherstash/auth-')
    const frozen = [...FROZEN_PUBLISHERS.keys()].filter(isAuth)
    const workspace = workspaceManifests()
      .map((manifest) => manifest.name)
      .filter(isAuth)

    expect([...new Set(guarded)].sort()).toHaveLength(7)
    expect([...new Set(guarded)].sort()).toEqual([...frozen].sort())
    expect([...new Set(guarded)].sort()).toEqual([...workspace].sort())
  })
})
