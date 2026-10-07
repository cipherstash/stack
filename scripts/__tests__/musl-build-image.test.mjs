import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * The linux-x64-musl binaries of `@cipherstash/auth` and
 * `@cipherstash/protect-ffi` are built in Alpine Linux, from
 * `.github/docker/musl-build/Dockerfile`, and published with provenance. Two
 * things about that image drift silently if an edit undoes them (#1042):
 *
 * 1. The base image digest is updated by nothing unless Dependabot's `docker`
 *    ecosystem reads the Dockerfile. Its `github-actions` ecosystem reads
 *    `uses:` lines only, so an image named inside a `run:` script is
 *    invisible to it — which is how the digest sat at its 2 October 2026
 *    value.
 * 2. An unpinned `apk add` installs whatever Alpine serves that day, so two
 *    builds of one commit can use different compilers.
 *
 * Both are only as good as there being ONE image: a second copy of the digest
 * in a workflow, or an `apk add` in a build script, is the drift this file
 * exists to catch.
 */

const DOCKERFILE_DIR = '.github/docker/musl-build'
const DOCKERFILE = `${DOCKERFILE_DIR}/Dockerfile`
const dockerfile = readFileSync(join(REPO_ROOT, DOCKERFILE), 'utf8')

const PINNED = /^node:\d+-alpine@sha256:[0-9a-f]{64}$/

/** A GitHub Actions expression, as the parsed workflow holds it. */
const gha = (expression) => `\${{ ${expression} }}`

/**
 * The build steps need these; a Dockerfile that lost one would still build.
 * `build-base` is a metapackage whose compiler and linker dependencies carry
 * no version, so the five it pulls in are pinned, and demanded, by name.
 */
const TOOLCHAIN = [
  'binutils',
  'build-base',
  'cmake',
  'curl',
  'g++',
  'gcc',
  'git',
  'linux-headers',
  'make',
  'musl-dev',
  'perl',
  'rustup',
]

/** The tools `musl-build-image.yml` checks for inside the built image. */
const TOOLS_CHECKED = [
  'cc',
  'c++',
  'cmake',
  'perl',
  'make',
  'curl',
  'git',
  'rustup-init',
  'node',
]

/** The Dockerfile's instructions, comments dropped and continuations joined. */
const instructions = dockerfile
  .split('\n')
  .filter((line) => !/^\s*#/.test(line))
  .join('\n')
  .replace(/\\\n/g, ' ')

/** Each `RUN apk add` in the Dockerfile, as its list of package arguments. */
function apkAdds(text) {
  return text
    .split('\n')
    .filter((line) => /^RUN\s+apk\s+add\b/.test(line))
    .map((line) =>
      line
        .replace(/^RUN\s+apk\s+add\s+/, '')
        .split(/\s+/)
        .filter((word) => word && !word.startsWith('--')),
    )
}

describe(DOCKERFILE, () => {
  it('starts from a node Alpine image pinned by digest', () => {
    // Read exactly as the preflights do, `sed -n 's/^FROM //p'`: one space
    // stripped, nothing trimmed, so a trailing space or CR that would make
    // `docker run` fail with "invalid reference format" fails here. One
    // stage, because a second would hand them two images.
    const froms = dockerfile
      .split('\n')
      .filter((line) => line.startsWith('FROM '))
      .map((line) => line.slice('FROM '.length))
    expect(froms).toHaveLength(1)
    expect(froms[0]).toMatch(PINNED)
  })

  it('reads every apk add in the Dockerfile, so none skips the pin check', () => {
    // `apkAdds` reads `RUN apk add …` lines only. An `apk add` after `&&`
    // would install unpinned and pass the test below, and `apk upgrade`
    // moves versions with no pin at all.
    const written = instructions.match(/\bapk\s+add\b/g) ?? []
    expect(written.length).toBeGreaterThan(0)
    expect(
      apkAdds(instructions),
      'An `apk add` is not at the start of a `RUN` line, so its packages are not checked for a `=version`.',
    ).toHaveLength(written.length)
    expect(instructions).not.toMatch(/\bapk\s+upgrade\b/)
  })

  it('pins every apk package to an exact version', () => {
    const adds = apkAdds(instructions)
    expect(adds.length).toBeGreaterThan(0)
    const packages = adds.flat()
    const unpinned = packages.filter(
      (pkg) => !/^[a-z0-9][a-z0-9._+-]*=[^=\s]+$/.test(pkg),
    )
    expect(
      unpinned,
      `These apk packages carry no \`=version\`, so \`apk add\` installs whatever Alpine serves on the day:\n${unpinned.map((p) => `  ${p}`).join('\n')}`,
    ).toEqual([])
  })

  it('installs the toolchain the build steps rely on', () => {
    const names = apkAdds(instructions)
      .flat()
      .map((pkg) => pkg.split('=')[0])
    for (const tool of TOOLCHAIN) expect(names).toContain(tool)
  })
})

describe('the workflows that use the image', () => {
  const workflows = workflowFiles().map((relPath) => ({
    relPath,
    text: readFileSync(join(REPO_ROOT, relPath), 'utf8'),
    wf: readWorkflow(relPath),
  }))
  const runsOf = (wf) =>
    Object.values(wf?.jobs ?? {}).flatMap((job) =>
      (Array.isArray(job?.steps) ? job.steps : []).map((step) =>
        String(step?.run ?? ''),
      ),
    )

  it('build the musl binaries from the Dockerfile, not from an inline image', () => {
    for (const relPath of [
      '.github/workflows/_build-auth-artifacts.yml',
      '.github/workflows/_build-ffi-artifacts.yml',
    ]) {
      const { wf } = workflows.find((w) => w.relPath === relPath)
      const run = runsOf(wf).find((text) => /\bdocker run\b/.test(text))
      expect(run, `${relPath} has no docker run step`).toBeDefined()
      // `--pull` fetches the digest the Dockerfile names, not a tag cached on
      // the runner, and the run step uses the tag the build step wrote.
      expect(run).toMatch(
        /docker build --pull -t "\$MUSL_BUILD_IMAGE" \.github\/docker\/musl-build\n[\s\S]*docker run[\s\S]*"\$MUSL_BUILD_IMAGE"/,
      )
    }
  })

  it('name the node Alpine image nowhere, so the Dockerfile is its one home', () => {
    // Pinned or not: a copy with no digest is worse than a stale one, because
    // the tag moves.
    const copies = workflows
      .filter(({ text }) => /\bnode:\d+-alpine\b/.test(text))
      .map(({ relPath }) => relPath)
    expect(
      copies,
      `These workflows name the node Alpine image themselves. Dependabot moves the digest in ${DOCKERFILE}, and a copy is left behind or was never pinned — read it from the Dockerfile as the preflights do.`,
    ).toEqual([])
  })

  it('install no apk packages of their own', () => {
    const offenders = workflows
      .filter(({ wf }) => runsOf(wf).some((text) => /\bapk add\b/.test(text)))
      .map(({ relPath }) => relPath)
    expect(
      offenders,
      `These workflows run \`apk add\` in a step. Packages the musl build needs belong in ${DOCKERFILE}, pinned.`,
    ).toEqual([])
  })

  it('smoke-test the musl artifacts on the image the Dockerfile starts from', () => {
    for (const relPath of [
      '.github/workflows/auth-preflight.yml',
      '.github/workflows/ffi-preflight.yml',
    ]) {
      const { wf } = workflows.find((w) => w.relPath === relPath)
      const run = runsOf(wf).find((text) => /\bdocker run\b/.test(text))
      expect(run, `${relPath} has no docker run step`).toBeDefined()
      expect(run).toContain(
        `ALPINE_NODE_IMAGE=$(sed -n 's/^FROM //p' ${DOCKERFILE})`,
      )
      expect(run).toMatch(/docker run[\s\S]*"\$ALPINE_NODE_IMAGE"/)
      // Both preflights sparse-checkout `scripts` alone; the Dockerfile has
      // to be in that list or the `sed` reads nothing and the step dies.
      const job = Object.values(wf.jobs).find((j) =>
        (j?.steps ?? []).some((s) => String(s?.run ?? '').includes(DOCKERFILE)),
      )
      const checkout = job.steps.find((s) =>
        String(s?.uses ?? '').startsWith('actions/checkout'),
      )
      const sparse = String(checkout?.with?.['sparse-checkout'] ?? '')
        .split('\n')
        .map((path) => path.trim())
        .filter(Boolean)
      if (sparse.length > 0) expect(sparse).toContain(DOCKERFILE_DIR)
    }
  })
})

describe('keeping the image current', () => {
  it('has a Dependabot docker entry for the Dockerfile directory', () => {
    const config = yaml.load(
      readFileSync(join(REPO_ROOT, '.github/dependabot.yml'), 'utf8'),
    )
    const docker = (config?.updates ?? []).filter(
      (update) => update['package-ecosystem'] === 'docker',
    )
    expect(docker.map((update) => update.directory)).toContain(
      `/${DOCKERFILE_DIR}`,
    )
    // Weekly, as the skill says. The cooldown on every entry is
    // supply-chain.e2e.test.ts's.
    const entry = docker.find(
      (update) => update.directory === `/${DOCKERFILE_DIR}`,
    )
    expect(entry).toMatchObject({ schedule: { interval: 'weekly' } })
  })

  it('builds the Dockerfile on a schedule and on every change to it', () => {
    const relPath = '.github/workflows/musl-build-image.yml'
    const wf = readWorkflow(relPath)
    const on = wf?.on ?? wf?.[true]
    expect(on?.schedule).toEqual([{ cron: '0 7 * * 1' }])
    for (const trigger of ['push', 'pull_request']) {
      expect(on?.[trigger]?.paths).toEqual(
        expect.arrayContaining([`${DOCKERFILE_DIR}/**`, relPath]),
      )
    }
    const runs = Object.values(wf?.jobs ?? {}).flatMap((job) =>
      (job?.steps ?? []).map((step) => String(step?.run ?? '')),
    )
    expect(
      runs.some(
        (run) =>
          run.includes(`docker build --pull`) && run.includes(DOCKERFILE_DIR),
      ),
    ).toBe(true)
    // A Dockerfile that builds but lost a tool would fail minutes into a
    // release build; the check step is what sees it first.
    const check = runs.find((run) => run.includes('for tool in'))
    expect(
      check,
      'no step checks the tools inside the built image',
    ).toBeDefined()
    const listed = check
      .match(/for tool in ([^;]+);/)[1]
      .trim()
      .split(/\s+/)
    expect(listed).toEqual(TOOLS_CHECKED)
    // A scheduled run's failure mails one person; the issue is for the rest.
    const steps = Object.values(wf?.jobs ?? {}).flatMap(
      (job) => job?.steps ?? [],
    )
    const notify = steps.find((step) =>
      String(step?.run ?? '').includes('gh issue create'),
    )
    expect(notify?.if).toBe(gha("failure() && github.event_name == 'schedule'"))
  })
})
