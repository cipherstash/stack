import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * `_build-ffi-artifacts.yml` builds the seven `@cipherstash/protect-ffi`
 * tarballs that `release.yml`'s `publish-ffi` uploads. Two things about its
 * Linux legs ship a broken package, rather than failing a build, if an edit
 * undoes them:
 *
 * 1. Every Linux binary's C library is checked before it is packed. Without
 *    the check, only a hand-run ffi-preflight sees a glibc-linked musl binary,
 *    which fails to load on musl systems such as Alpine Linux.
 * 2. The musl binary is built inside Alpine Linux, from an image pinned by
 *    digest, and loaded there. Its toolchain used to come from musl.cc, which
 *    timed out from GitHub's runners on six tries on 2 October 2026.
 */

const workflow = readWorkflow('.github/workflows/_build-ffi-artifacts.yml')
const steps = workflow?.jobs?.binaries?.steps ?? []
const runOf = (step) => String(step?.run ?? '')
const named = (name) => steps.findIndex((step) => step?.name === name)

/** A GitHub Actions expression, as the parsed workflow holds it. */
const gha = (expression) => `\${{ ${expression} }}`

const MUSL = "matrix.cfg.platform == 'linux-x64-musl'"
const NOT_MUSL = "matrix.cfg.platform != 'linux-x64-musl'"
const PINNED = /^node:\d+-alpine@sha256:[0-9a-f]{64}$/

describe('_build-ffi-artifacts.yml', () => {
  it('checks the C library of every Linux binary before it is packed', () => {
    const check = steps.findIndex((step) =>
      runOf(step).includes('scripts/check-c-library.sh'),
    )
    const pack = named('Pack the platform package')
    expect(pack).toBeGreaterThan(-1)
    // After both ways a binary is placed in its platform package.
    for (const place of [
      named('Place the binding in its platform package'),
      named('Build the binding in Alpine (linux-x64-musl)'),
    ]) {
      expect(place).toBeGreaterThan(-1)
      expect(check).toBeGreaterThan(place)
    }
    expect(check).toBeLessThan(pack)
    expect(String(steps[check].if)).toContain("runner.os == 'Linux'")
    // The binary that is packed, under the leg's own platform name.
    expect(steps[check].env?.PLATFORM).toBe(gha('matrix.cfg.platform'))
    expect(runOf(steps[check])).toMatch(
      /check-c-library\.sh "\$PLATFORM" "languages\/typescript\/packages\/protect-ffi\/platforms\/\$\{PLATFORM\}\/index\.node"/,
    )
  })

  it('builds the musl binding inside Alpine, from an image pinned by digest', () => {
    const musl = steps.filter((step) => String(step?.if ?? '').includes(MUSL))
    expect(musl).toHaveLength(1)
    const [build] = musl
    const run = runOf(build)
    expect(build.env?.ALPINE_NODE_IMAGE).toMatch(PINNED)
    // The pinned image is the one that runs, not a mutable tag.
    expect(run).toMatch(/docker run[\s\S]*"\$ALPINE_NODE_IMAGE"/)
    expect(run).not.toMatch(/\bnode:\d+-alpine(?!@)/)
    expect(run).toContain('RUSTFLAGS="-C target-feature=-crt-static"')
    // The container hands its files back even when the build fails.
    expect(run).toMatch(/^\s*trap "chown -R .*\/build" EXIT$/m)
    // The matrix decides the target, build script and log, as on the other
    // legs, and the container is given all of them.
    expect(build.env).toMatchObject({
      CARGO_BUILD_TARGET: gha('matrix.cfg.target'),
      PLATFORM: gha('matrix.cfg.platform'),
      BUILD_SCRIPT: gha('matrix.cfg.script'),
      BUILD_LOG: gha('matrix.cfg.log'),
    })
    for (const name of [
      'CARGO_BUILD_TARGET',
      'PLATFORM',
      'BUILD_SCRIPT',
      'BUILD_LOG',
    ]) {
      expect(run).toMatch(new RegExp(`-e ${name}\\b`))
    }
    // Build, place, then load the placed binary, on musl.
    expect(run).toMatch(
      /pnpm run "\$BUILD_SCRIPT"[\s\S]*neon dist -n protect-ffi -o "platforms\/\$PLATFORM\/index\.node" < "\$BUILD_LOG"[\s\S]*node -e "require\(process\.argv\[1\]\)" "\$PWD\/platforms\/\$PLATFORM\/index\.node"/,
    )
  })

  it('runs no host build step on the musl leg', () => {
    for (const name of [
      'Add the Rust target',
      'Install node-gyp',
      'Install dependencies',
      'Build binding',
      'Place the binding in its platform package',
    ]) {
      const step = steps[named(name)]
      expect(step, name).toBeDefined()
      expect(String(step?.if ?? ''), name).toContain(NOT_MUSL)
    }
  })

  it('downloads no toolchain from musl.cc', () => {
    // The parsed workflow, so the comment that records why is not counted.
    expect(JSON.stringify(workflow)).not.toMatch(/musl\.cc/)
  })

  it('pins mise in every mise step, at the auth release build version', () => {
    // Unpinned, the action installs the newest mise. mise 2026.10.0 refused
    // to install cargo-zigbuild, and both gnu legs failed.
    const miseSteps = (wf) =>
      Object.values(wf?.jobs ?? {}).flatMap((job) =>
        (job?.steps ?? []).filter((step) =>
          String(step?.uses ?? '').startsWith('jdx/mise-action@'),
        ),
      )
    const [auth] = miseSteps(
      readWorkflow('.github/workflows/_build-auth-artifacts.yml'),
    )
    expect(auth?.with?.version).toMatch(/^\d{4}\.\d+\.\d+$/)
    const ffi = miseSteps(workflow)
    expect(ffi.length).toBeGreaterThanOrEqual(2)
    for (const step of ffi) {
      expect(step.with?.version, step.name).toBe(auth.with.version)
    }
  })
})

describe('ffi-preflight.yml', () => {
  const preflight = readWorkflow('.github/workflows/ffi-preflight.yml')
  const smoke = preflight?.jobs?.smoke?.steps ?? []

  it('checks the C library of every Linux binary with the shared script', () => {
    const verify = smoke.map(runOf).join('\n')
    expect(verify).toMatch(
      /if \[\[ "\$platform" == linux-\* \]\]; then\s+"\$GITHUB_WORKSPACE\/scripts\/check-c-library\.sh" "\$platform" x\/package\/index\.node/,
    )
    // The script comes from the commit that was built, and the checkout comes
    // first, because a checkout empties the directory it checks out into.
    const checkout = smoke.findIndex((step) =>
      String(step?.uses ?? '').startsWith('actions/checkout@'),
    )
    const download = smoke.findIndex((step) =>
      String(step?.uses ?? '').startsWith('actions/download-artifact@'),
    )
    expect(checkout).toBeGreaterThan(-1)
    expect(checkout).toBeLessThan(download)
    expect(smoke[checkout].with?.ref).toBe(gha('inputs.ref'))
  })

  it('loads the musl artifact inside Alpine', () => {
    // The host smoke test installs only the runner's own platform, so without
    // this step no job loads the musl package that was packed.
    const alpine = smoke.find((step) => /\bdocker run\b/.test(runOf(step)))
    expect(alpine).toBeDefined()
    const run = runOf(alpine)
    expect(run).toMatch(/docker run[\s\S]*"\$ALPINE_NODE_IMAGE"/)
    expect(run).toContain('cipherstash-protect-ffi-linux-x64-musl-')
    expect(run).toMatch(
      /npm install [^\n]*"\/dist\/\$WRAPPER" "\/dist\/\$MUSL"/,
    )
    // A bare require loads nothing: the binding resolves on first use.
    expect(run).toContain('ffi.assertNativeBindingAvailable()')
  })
})

describe('the Alpine image', () => {
  it('is one pinned image in every workflow, so a load test matches its build', () => {
    const images = workflowFiles().flatMap((file) =>
      Object.values(readWorkflow(file)?.jobs ?? {}).flatMap((job) =>
        (job?.steps ?? [])
          .map((step) => step?.env?.ALPINE_NODE_IMAGE)
          .filter(Boolean),
      ),
    )
    // Both builds and both preflights.
    expect(images.length).toBeGreaterThanOrEqual(4)
    expect(new Set(images).size).toBe(1)
    expect(images[0]).toMatch(PINNED)
  })
})
