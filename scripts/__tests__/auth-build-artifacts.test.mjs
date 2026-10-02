import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `_build-auth-artifacts.yml` builds the seven `@cipherstash/auth` tarballs
 * that `release.yml`'s `publish-auth` uploads. Three things about it are easy
 * to undo in an edit that still looks right, and each one ships a broken
 * package rather than failing a build:
 *
 * 1. `napi build --platform` with no `--js false` writes napi's own loader over
 *    the committed `index.js`, one of the wrapper's frozen published files.
 *    The workflow runs `git diff --exit-code` on the package after the build,
 *    so the build must leave the tracked tree as it found it.
 * 2. The wrapper's six platform peers are `workspace:*`. `pnpm pack` rewrites
 *    them to the exact version; `npm pack` publishes `workspace:*`, which no
 *    registry resolves.
 * 3. The matrix is a third list of the six platforms, beside the `platforms/`
 *    folders and the napi triples in the wrapper's `package.json`.
 */

const WORKFLOW = '.github/workflows/_build-auth-artifacts.yml'
const AUTH_DIR = 'languages/typescript/packages/auth'
const AUTH = join(REPO_ROOT, AUTH_DIR)

const workflow = readWorkflow(WORKFLOW)
const binaries = workflow?.jobs?.binaries
const wrapper = workflow?.jobs?.wrapper
const runs = (job) => (job?.steps ?? []).map((step) => String(step?.run ?? ''))

const PLATFORMS = readdirSync(join(AUTH, 'platforms'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()

describe('_build-auth-artifacts.yml', () => {
  it('builds every platform package, and only those', () => {
    const matrix = binaries?.strategy?.matrix?.include ?? []
    expect(PLATFORMS).toHaveLength(6)
    expect(matrix.map((leg) => leg.platform).sort()).toEqual(PLATFORMS)

    const { napi } = JSON.parse(
      readFileSync(join(AUTH, 'package.json'), 'utf8'),
    )
    expect(matrix.map((leg) => leg.target).sort()).toEqual(
      [...napi.triples.additional].sort(),
    )
  })

  it('builds each binding without writing over the committed loader', () => {
    const build = runs(binaries).filter((run) => /\bnapi build\b/.test(run))
    // One host build, and one inside Alpine for the musl leg.
    expect(build).toHaveLength(2)
    for (const flag of [
      '--platform',
      '--release',
      '--target',
      '--strip',
      '--dts native.d.ts',
      '--js false',
    ]) {
      for (const run of build) expect(run).toContain(flag)
    }
  })

  it('fails the leg when either build changed a tracked file', () => {
    const all = runs(binaries)
    const builds = all
      .map((_, index) => index)
      .filter((index) => /\bnapi build\b/.test(all[index]))
    const check = all.findIndex((run) =>
      new RegExp(`git diff --exit-code\\b.*${AUTH_DIR}`).test(run),
    )
    expect(builds).toHaveLength(2)
    for (const build of builds) expect(check).toBeGreaterThan(build)
  })

  it('builds the musl binding inside Alpine, from an image pinned by digest', () => {
    // Built on the Ubuntu runner, the musl binary linked glibc and failed to
    // load on musl. Alpine is a musl system, so its compiler links musl.
    const steps = binaries?.steps ?? []
    const musl = steps.filter((step) =>
      String(step?.if ?? '').includes("== 'linux-x64-musl'"),
    )
    const run = musl.map((step) => String(step?.run ?? '')).join('\n')
    const env = Object.assign({}, ...musl.map((step) => step?.env ?? {}))
    expect(env.ALPINE_NODE_IMAGE).toMatch(/-alpine@sha256:[0-9a-f]{64}$/)
    // The pinned image is the one that runs, not a mutable tag.
    expect(run).toMatch(/docker run[\s\S]*"\$ALPINE_NODE_IMAGE"/)
    expect(run).not.toMatch(/\bnode:\d+-alpine(?!@)/)
    expect(run).toContain('RUSTFLAGS="-C target-feature=-crt-static"')
    // The container loads the binary it built, on musl.
    expect(run).toMatch(
      /napi build[\s\S]*node -e "require\(process\.argv\[1\]\)" "\$PWD\/stack-auth-node\.linux-x64-musl\.node"/,
    )
    // The container hands its files back even when the build fails.
    expect(run).toMatch(/^\s*trap "chown -R .*\/build" EXIT$/m)
    // The host steps that only the host build uses skip the musl leg.
    for (const name of [
      'Add the Rust target',
      'Install node-gyp',
      'Install dependencies',
      'Build the native binding',
    ]) {
      const step = steps.find((s) => s?.name === name)
      expect(String(step?.if ?? '')).toContain("!= 'linux-x64-musl'")
    }
  })

  it('checks the C library of every Linux binary before it is packed', () => {
    // Without this, only a hand-run auth-preflight sees a glibc-linked musl
    // binary, and a release would publish it.
    const steps = binaries?.steps ?? []
    const check = steps.findIndex((step) =>
      String(step?.run ?? '').includes('readelf -d'),
    )
    const pack = steps.findIndex((step) =>
      /\bnpm pack\b/.test(String(step?.run ?? '')),
    )
    expect(check).toBeGreaterThan(-1)
    expect(check).toBeLessThan(pack)
    const run = String(steps[check].run)
    expect(String(steps[check].if)).toContain("runner.os == 'Linux'")
    expect(run).toMatch(
      /linux-x64-gnu\|linux-arm64-gnu\)[\s\S]*libc\\\.so\\\.6/,
    )
    expect(run).toContain('linux-x64-musl links glibc')
    // A static binary has no libc entry, so musl must be named, not only
    // glibc refused.
    expect(run).toMatch(/linux-x64-musl\)[\s\S]*libc\\\.musl-/)
    // Every rejection fails the job, so the binary is never packed.
    const errors = run.match(/::error::/g) ?? []
    expect(errors.length).toBeGreaterThan(0)
    expect((run.match(/exit 1/g) ?? []).length).toBe(errors.length)
    // Every Linux platform in the matrix has a rule.
    const linux = (binaries?.strategy?.matrix?.include ?? [])
      .filter((leg) => String(leg.os).startsWith('ubuntu'))
      .map((leg) => leg.platform)
    expect(linux.length).toBeGreaterThan(0)
    for (const platform of linux) {
      expect(run).toMatch(new RegExp(`(^|[|\\s])${platform}[|)]`, 'm'))
    }
  })

  it('auth-preflight requires musl, and loads the musl artifact inside Alpine', () => {
    const preflight = readWorkflow('.github/workflows/auth-preflight.yml')
    const steps = preflight?.jobs?.smoke?.steps ?? []
    const verify = steps.map((step) => String(step?.run ?? '')).join('\n')
    expect(verify).toMatch(/linux-x64-musl\)[\s\S]*libc\\\.musl-/)
    // The host smoke test installs only the runner's own platform, so without
    // this step no job loads the musl binary.
    const alpine = steps.find((step) =>
      /\bdocker run\b/.test(String(step?.run ?? '')),
    )
    expect(alpine).toBeDefined()
    expect(String(alpine.run)).toContain('linux-x64-musl')
    expect(String(alpine.run)).toMatch(/docker run[\s\S]*"\$ALPINE_NODE_IMAGE"/)
    // The same image as the build, so the load test matches the build.
    const build = (binaries?.steps ?? []).find(
      (step) => step?.env?.ALPINE_NODE_IMAGE,
    )
    expect(alpine.env?.ALPINE_NODE_IMAGE).toBe(build?.env?.ALPINE_NODE_IMAGE)
  })

  it('packs the wrapper with pnpm, which rewrites its workspace peers', () => {
    const packs = runs(wrapper).filter((run) => /\bpack\b/.test(run))
    expect(packs.some((run) => /\bpnpm\b.*\bpack\b/.test(run))).toBe(true)
    expect(packs.some((run) => /\bnpm pack\b/.test(run))).toBe(false)
  })
})
