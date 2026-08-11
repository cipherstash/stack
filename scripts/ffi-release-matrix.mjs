/**
 * The release build matrix for the six `@cipherstash/protect-ffi-<platform>`
 * packages: one entry per platform, carrying everything the job needs that
 * cannot be derived inside it.
 *
 * WHY THIS IS A FILE AND NOT FIFTEEN LINES OF `node -e` IN THE WORKFLOW. Three
 * of the four fields are wrong if the upstream matrix is copied across
 * verbatim, and each is wrong silently:
 *
 *   target — upstream derives the Rust triple from `neon list-platforms` and
 *     passes it as CARGO_BUILD_TARGET, and every cross-compilation detail hangs
 *     off it. Omit it and cargo builds for the runner: `macos-latest` is
 *     arm64 today, so BOTH Darwin jobs would emit ARM64 and `darwin-x64` would
 *     ship a binary that installs cleanly and fails to dlopen.
 *
 *   script — upstream's non-gnu platforms select `build`, which upstream had as
 *     its cargo script. HERE `build` IS `tsc` AND NOTHING ELSE: phase 1 of the
 *     absorption moved cargo to `build:native` deliberately, so that the
 *     default test and build paths stay Rust-free. Ported as-is, four of the
 *     six platforms would run a TypeScript compile, produce no binary, and fail
 *     one step later on a missing log file.
 *
 *   log — `cargo-build` redirects to `cargo.log`, `zig-build` to `zig.log`, and
 *     `neon dist` reads that file to locate the artifact it just built. A
 *     single hardcoded `< cargo.log` is wrong for whichever half it does not
 *     match.
 *
 * All three are the kind of mistake that produces a green matrix and a broken
 * tarball, so they live here with `scripts/__tests__/ffi-release-matrix.test.mjs`
 * checking them against the package's actual scripts rather than against a copy
 * of this reasoning.
 */
import { appendFileSync, readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const PLATFORMS_DIR = join(REPO_ROOT, 'packages/protect-ffi/platforms')

/**
 * Where each platform builds.
 *
 * Linux goes to Blacksmith (the repo's standard Linux runner); the Darwin and
 * Windows builds need GitHub-hosted images for their SDKs. Both Darwin
 * platforms share `macos-latest` and cross-compile — which is exactly why
 * `target` is explicit.
 */
export function runnerFor(platform) {
  if (platform.startsWith('win32')) return 'windows-latest'
  if (platform.startsWith('darwin')) return 'macos-latest'
  return 'blacksmith-4vcpu-ubuntu-2404'
}

/**
 * gnu targets cross-compile through cargo-zigbuild so the glibc floor can be
 * pinned (`--target <triple>.2.28`); everything else builds with plain cargo.
 * The two scripts redirect to different log files — see the header.
 */
export function buildFor(platform) {
  return platform.includes('gnu')
    ? { script: 'zigbuild', log: 'zig.log' }
    : { script: 'build:native', log: 'cargo.log' }
}

/**
 * Platform name -> Rust target triple, read from the platform packages
 * themselves: each `platforms/<name>/package.json` carries `neon.rust`, written
 * there by `neon add-platform` and shipped inside the published tarball.
 *
 * `neon list-platforms` prints the same mapping, and the matrix used to shell
 * out to it — which meant a cold full-workspace install (~1GB, no caching
 * allowed in a publishing workflow) on the critical path ahead of all six
 * builds, to read six fields that are committed to this repository.
 * `ffi-release-matrix.test.mjs` pins this against the fixture taken from
 * `neon list-platforms`, so the two cannot drift silently.
 */
export function triplesFromPlatformManifests(dir = PLATFORMS_DIR) {
  const entries = readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  return Object.fromEntries(
    entries.map((platform) => {
      const pkg = JSON.parse(
        readFileSync(join(dir, platform, 'package.json'), 'utf8'),
      )
      return [pkg.neon.node, pkg.neon.rust]
    }),
  )
}

/**
 * `triples` is a platform name -> Rust target triple mapping, as
 * `triplesFromPlatformManifests()` (or `neon list-platforms`) produces.
 */
export function releaseMatrix(triples) {
  return Object.entries(triples).map(([platform, target]) => ({
    platform,
    target,
    os: runnerFor(platform),
    ...buildFor(platform),
  }))
}

function main() {
  // `argv[2]` overrides the tree, for checking a mapping by hand; with no
  // argument this reads the platform packages and needs nothing installed.
  const triples = process.argv[2]
    ? JSON.parse(process.argv[2])
    : triplesFromPlatformManifests()
  const matrix = releaseMatrix(triples)

  if (matrix.length === 0) {
    // An empty matrix builds nothing, uploads nothing, and reports success —
    // and the next job would then pack the wrapper against six platform
    // packages that were never built.
    console.error('release matrix is empty: no platform packages found')
    process.exit(1)
  }

  console.error(JSON.stringify(matrix, null, 2))
  const result = JSON.stringify(matrix)
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `result=${result}\n`)
  }
  console.log(result)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
