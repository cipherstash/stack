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
import { appendFileSync } from 'node:fs'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

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
 * `triples` is `neon list-platforms` output: platform name -> Rust target
 * triple. That command is the ONLY source of the mapping — `neon.platforms` in
 * package.json lists names, not triples.
 */
export function releaseMatrix(triples) {
  return Object.entries(triples).map(([platform, target]) => ({
    platform,
    target,
    os: runnerFor(platform),
    ...buildFor(platform),
  }))
}

/**
 * The mapping, from `argv[2]` if given and otherwise from stdin.
 *
 * Async iteration rather than `readFileSync(0)`: a pipe hands Node a
 * non-blocking fd, and the synchronous read throws `EAGAIN` on it — which is
 * how the CI spelling (`neon list-platforms | node …`) fails while reading the
 * same bytes from a file succeeds.
 */
async function readMapping() {
  if (process.argv[2]) return process.argv[2]
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8')
}

async function main() {
  const triples = JSON.parse(await readMapping())
  const matrix = releaseMatrix(triples)

  if (matrix.length === 0) {
    // An empty matrix builds nothing, uploads nothing, and reports success —
    // and the next job would then pack the wrapper against six platform
    // packages that were never built.
    console.error(
      'release matrix is empty: neon list-platforms returned no platforms',
    )
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
