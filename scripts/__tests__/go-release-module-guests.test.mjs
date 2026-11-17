import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * release-golang.yml's `verify` job checks each Go module zip the proxy
 * serves against the guests that belong to that module.
 * scripts/go-release-module-guests.sh decides which those are.
 */

const SCRIPT = join(REPO_ROOT, 'scripts/go-release-module-guests.sh')
const WORKFLOW = readWorkflow('.github/workflows/release-golang.yml')
const MODULES = String(WORKFLOW.env.MODULES).split(/\s+/).filter(Boolean)
const GUESTS = String(WORKFLOW.env.GUESTS).split(/\s+/).filter(Boolean)

let dir

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'go-release-guests-'))
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

/** The release's manifest: one fake SHA-256 line per guest, in order. */
function manifest() {
  const path = join(dir, 'guests.sha256')
  writeFileSync(
    path,
    GUESTS.map((guest, i) => `${String(i).repeat(64)}  ${guest}`).join('\n') +
      '\n',
  )
  return path
}

function pick(module, modules = MODULES) {
  return spawnSync('bash', [SCRIPT, manifest(), module, ...modules], {
    encoding: 'utf8',
  })
}

describe('go-release-module-guests.sh', () => {
  it('gives the SDK its three guests, relative to its directory', () => {
    const result = pick('languages/golang')
    expect(result.status, result.stderr).toBe(0)
    expect(result.stdout.trim().split('\n')).toEqual([
      `${'0'.repeat(64)}  encrypt/wasm/stack_encrypt_guest.wasm`,
      `${'1'.repeat(64)}  encrypt/eql/wasm/stack_encrypt_guest_eql.wasm`,
      `${'2'.repeat(64)}  auth/wasm/stack_auth_guest.wasm`,
    ])
  })

  it('gives encrypttest the two test builds, though the SDK directory is above them too', () => {
    const result = pick('languages/golang/encrypt/encrypttest')
    expect(result.status, result.stderr).toBe(0)
    expect(result.stdout.trim().split('\n')).toEqual([
      `${'3'.repeat(64)}  wasm/stack_encrypt_guest_deterministic.wasm`,
      `${'4'.repeat(64)}  wasm/stack_encrypt_guest_eql_deterministic.wasm`,
    ])
  })

  it('refuses a module no guest belongs to', () => {
    const result = pick('languages/golang/cmd')
    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('no guest')
  })

  it('is what verify checks each module zip against', () => {
    const verify = WORKFLOW.jobs.verify.steps.find(
      (step) => step.name === 'Download the version through the Go proxy',
    )
    expect(String(verify.run)).toContain('scripts/go-release-module-guests.sh')
    expect(String(verify.run)).toContain('for module_dir in $MODULES')
  })
})
