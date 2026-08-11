import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  buildFor,
  releaseMatrix,
  runnerFor,
  triplesFromPlatformManifests,
} from '../ffi-release-matrix.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The release matrix decides what each of the six platform jobs compiles and
 * where it looks for the result. Every field it carries is one the upstream
 * matrix got right for upstream and wrong here — see the header of
 * `scripts/ffi-release-matrix.mjs`.
 *
 * These checks are derived from `packages/protect-ffi/package.json` rather than
 * restated: the script the matrix names must exist, and the log file it names
 * must be the one that script actually redirects to. Rename a script or move a
 * redirect and this fails, which is the only way the matrix stays true to the
 * package.
 */

const FFI = join(REPO_ROOT, 'packages/protect-ffi')
const pkg = JSON.parse(readFileSync(join(FFI, 'package.json'), 'utf8'))

/**
 * `neon list-platforms` output, verbatim, as of the six platforms this package
 * publishes.
 *
 * This is the INDEPENDENT copy. The matrix reads the same mapping out of each
 * `platforms/<name>/package.json` (`neon.rust`) so the release job needs
 * nothing installed, and the check below asserts the two agree — without it,
 * deriving from the manifests would just be trusting the manifests.
 */
const TRIPLES = {
  'darwin-x64': 'x86_64-apple-darwin',
  'darwin-arm64': 'aarch64-apple-darwin',
  'win32-x64-msvc': 'x86_64-pc-windows-msvc',
  'linux-x64-gnu': 'x86_64-unknown-linux-gnu',
  'linux-arm64-gnu': 'aarch64-unknown-linux-gnu',
  'linux-x64-musl': 'x86_64-unknown-linux-musl',
}

/**
 * The log file a script's chain redirects to, resolved through one `pnpm run`
 * hop: `build:native` -> `cargo-build` -> `… > cargo.log`.
 */
function logFileOf(scriptName) {
  const body = pkg.scripts[scriptName]
  if (body === undefined) return null
  const hop = body.match(/pnpm run ([\w:-]+)/)
  const resolved = hop ? pkg.scripts[hop[1]] : body
  const redirect = String(resolved).match(/>\s*(\S+\.log)/)
  return redirect ? redirect[1] : null
}

const MATRIX = releaseMatrix(TRIPLES)

describe('the platform fixture matches the package', () => {
  it('covers exactly the platforms this package publishes', () => {
    expect(Object.keys(TRIPLES).sort()).toEqual([...pkg.neon.platforms].sort())
  })

  it('agrees with the triples committed in the platform packages', () => {
    // The mapping the release matrix actually uses. A platform package whose
    // `neon.rust` drifts from what neon computes would cross-compile for the
    // wrong target under a name that says otherwise — the tarball installs and
    // then fails to dlopen, which is the failure this whole matrix exists to
    // prevent.
    expect(triplesFromPlatformManifests()).toEqual(TRIPLES)
  })
})

describe('release matrix', () => {
  it('produces one entry per platform', () => {
    expect(MATRIX).toHaveLength(6)
    expect(MATRIX.map((entry) => entry.platform).sort()).toEqual(
      Object.keys(TRIPLES).sort(),
    )
  })

  it('carries the Rust triple for every platform', () => {
    // Without this, cargo builds for the runner's own architecture — and both
    // Darwin platforms share an arm64 runner, so `darwin-x64` would ship an ARM
    // binary that installs cleanly and fails to load.
    for (const entry of MATRIX) {
      expect(entry.target).toBe(TRIPLES[entry.platform])
    }
  })

  it('never selects `build`, which is tsc and emits no binary', () => {
    // The single most likely port defect: upstream's `build` WAS its cargo
    // script. Here it is `tsc` and nothing else.
    expect(pkg.scripts.build).toBe('tsc')
    for (const entry of MATRIX) {
      expect(entry.script).not.toBe('build')
    }
  })

  it('names a script that exists', () => {
    for (const entry of MATRIX) {
      expect(
        pkg.scripts[entry.script],
        `${entry.platform} selects "${entry.script}", which packages/protect-ffi/package.json does not define`,
      ).toBeDefined()
    }
  })

  it('names the log file that script actually redirects to', () => {
    // `neon dist` reads this file to locate the compiled artifact, so a matrix
    // that names the wrong one fails after the compile has already been paid
    // for — or, worse, reads a stale log from the other build.
    for (const entry of MATRIX) {
      expect(
        entry.log,
        `${entry.platform} reads ${entry.log}, but ${entry.script} redirects to ${logFileOf(entry.script)}`,
      ).toBe(logFileOf(entry.script))
    }
  })

  it('routes every platform to the runner and build it needs', () => {
    // A LITERAL TABLE, not the ladder re-typed. Both of these were previously
    // asserted by re-implementing `runnerFor`/`buildFor` in the expectation —
    // which cannot fail for the error it looks like it guards: a wrong rule in
    // the script passes as long as the copy in the test is edited the same
    // wrong way. Spelled as data, every field of every platform is pinned, and
    // changing a rule means changing rows here.
    //
    // zigbuild is how the gnu glibc floor gets pinned (`--target
    // <triple>.2.28`); applying it to musl or Darwin would be a different build
    // entirely. Both Darwin platforms share one runner and cross-compile, which
    // is why `target` is explicit.
    expect(MATRIX).toEqual([
      {
        platform: 'darwin-x64',
        target: 'x86_64-apple-darwin',
        os: 'macos-latest',
        script: 'build:native',
        log: 'cargo.log',
      },
      {
        platform: 'darwin-arm64',
        target: 'aarch64-apple-darwin',
        os: 'macos-latest',
        script: 'build:native',
        log: 'cargo.log',
      },
      {
        platform: 'win32-x64-msvc',
        target: 'x86_64-pc-windows-msvc',
        os: 'windows-latest',
        script: 'build:native',
        log: 'cargo.log',
      },
      {
        platform: 'linux-x64-gnu',
        target: 'x86_64-unknown-linux-gnu',
        os: 'blacksmith-4vcpu-ubuntu-2404',
        script: 'zigbuild',
        log: 'zig.log',
      },
      {
        platform: 'linux-arm64-gnu',
        target: 'aarch64-unknown-linux-gnu',
        os: 'blacksmith-4vcpu-ubuntu-2404',
        script: 'zigbuild',
        log: 'zig.log',
      },
      {
        platform: 'linux-x64-musl',
        target: 'x86_64-unknown-linux-musl',
        os: 'blacksmith-4vcpu-ubuntu-2404',
        script: 'build:native',
        log: 'cargo.log',
      },
    ])
  })

  it('sends a platform the table does not name to a Linux runner', () => {
    // The fallback arm, which the table above cannot reach. A seventh platform
    // added tomorrow gets Blacksmith unless `runnerFor` is taught otherwise.
    expect(runnerFor('linux-arm64-musl')).toBe('blacksmith-4vcpu-ubuntu-2404')
  })

  it('is empty for an empty mapping, rather than inventing platforms', () => {
    // The CLI turns this into a hard failure: a matrix of zero builds nothing,
    // uploads nothing, and reports success.
    expect(releaseMatrix({})).toEqual([])
  })

  it('exposes the script/log pair as one decision', () => {
    // Both fields come from the same call, so they cannot be edited apart.
    expect(buildFor('linux-arm64-gnu')).toEqual({
      script: 'zigbuild',
      log: 'zig.log',
    })
    expect(buildFor('darwin-x64')).toEqual({
      script: 'build:native',
      log: 'cargo.log',
    })
  })
})
