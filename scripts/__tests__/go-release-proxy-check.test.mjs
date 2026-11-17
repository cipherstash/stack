import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `release-golang.yml` refuses a version the Go proxy already lists, which
 * catches a tag deleted after the proxy fetched it. The check must read
 * `@v/list` and never ask for the version itself: a request for a version
 * whose tag does not exist yet makes the proxy cache "not found" for up to 30
 * minutes, and the `verify` job, which asks for it straight after the push,
 * would then fail.
 */

const WORKFLOW = readWorkflow('.github/workflows/release-golang.yml')
const STEP_NAME = 'Refuse a version the Go proxy already lists'
const BUILD_STEPS = WORKFLOW.jobs.build.steps
const PROXY_STEP = BUILD_STEPS.find((step) => step.name === STEP_NAME)

let bin

beforeEach(() => {
  bin = mkdtempSync(join(tmpdir(), 'go-release-proxy-'))
})

afterEach(() => {
  rmSync(bin, { recursive: true, force: true })
})

/**
 * Run the step with a `curl` that answers `list` with HTTP `status`, as
 * `curl -o <file> -w '%{http_code}'` does, or fails to connect when `list`
 * is null. Each URL the step asks for is appended to `asked`.
 */
function runWithProxyList(version, list, status = 200) {
  const curl = join(bin, 'curl')
  const asked = join(bin, 'asked')
  writeFileSync(
    curl,
    list === null
      ? '#!/bin/sh\necho "curl: (7) Failed to connect" >&2\nexit 7\n'
      : `#!/bin/sh
out=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;;
    http*) echo "$1" >> '${asked}' ;;
  esac
  shift
done
printf '%s' '${list}' > "$out"
printf '%s' '${status}'
`,
  )
  chmodSync(curl, 0o755)
  const result = spawnSync('bash', ['-c', String(PROXY_STEP.run)], {
    encoding: 'utf8',
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      VERSION: version,
      MODULES: WORKFLOW.env.MODULES,
    },
  })
  return { ...result, asked: () => readFileSync(asked, 'utf8') }
}

describe('release-golang.yml: the Go proxy check', () => {
  it('runs in build, before anything is built', () => {
    const check = BUILD_STEPS.indexOf(PROXY_STEP)
    const firstBuild = BUILD_STEPS.findIndex((step) =>
      String(step.run ?? '').includes('mise run'),
    )
    expect(check).toBeGreaterThanOrEqual(0)
    expect(check).toBeLessThan(firstBuild)
  })

  it('reads @v/list and nothing else', () => {
    expect(String(PROXY_STEP.run)).toContain(
      'https://proxy.golang.org/$module/@v/list',
    )
  })

  it('is the only step before the push that talks to the proxy', () => {
    // Anything that resolves the version through the proxy before the tag
    // exists caches "not found" against it. `echo` lines are text for the
    // release notes, such as the `go get` a user runs, not commands.
    const commands = (run) =>
      String(run ?? '')
        .split('\n')
        .filter((line) => !/^\s*echo /.test(line))
        .join('\n')
    const asksForAVersion =
      /go (mod download|list -m|get)|@v\/v|\.info\b|@latest/
    for (const job of ['build', 'publish']) {
      for (const step of WORKFLOW.jobs[job].steps) {
        expect(commands(step.run), `${job}: ${step.name}`).not.toMatch(
          asksForAVersion,
        )
      }
    }
  })

  it('passes a version the proxy does not list', () => {
    const result = runWithProxyList(
      '0.1.0-alpha.1',
      'v0.1.0-alpha.10\nv0.1.0-alpha.2\n',
    )
    expect(result.stdout).not.toContain('::error::')
    expect(result.status).toBe(0)
  })

  it('reads the list of every module the release tags', () => {
    const result = runWithProxyList('0.1.0-alpha.1', '')
    expect(result.status, result.stderr).toBe(0)
    expect(result.asked().trim().split('\n')).toEqual([
      'https://proxy.golang.org/github.com/cipherstash/stack/languages/golang/@v/list',
      'https://proxy.golang.org/github.com/cipherstash/stack/languages/golang/encrypt/encrypttest/@v/list',
    ])
  })

  it('passes when the proxy lists nothing yet', () => {
    expect(runWithProxyList('0.1.0-alpha.1', '').status).toBe(0)
  })

  it('refuses a version the proxy lists', () => {
    const result = runWithProxyList(
      '0.1.0-alpha.1',
      'v0.1.0-alpha.1\nv0.1.0-alpha.2\n',
    )
    expect(result.status).toBe(1)
    expect(result.stdout).toContain('::error::the Go proxy already lists')
  })

  it('passes a module the proxy has never fetched, which it answers 404', () => {
    const result = runWithProxyList('0.1.0-alpha.1', 'not found', 404)
    expect(result.stdout).not.toContain('::error::')
    expect(result.status).toBe(0)
  })

  it('fails closed on any other HTTP status', () => {
    const result = runWithProxyList('0.1.0-alpha.1', 'oops', 500)
    expect(result.status).toBe(1)
    expect(result.stdout).toContain('::error::could not read')
    expect(result.stdout).toContain('HTTP 500')
  })

  it('fails closed when the proxy cannot be read', () => {
    const result = runWithProxyList('0.1.0-alpha.1', null)
    expect(result.status).toBe(1)
    expect(result.stdout).toContain('::error::could not read')
  })
})
