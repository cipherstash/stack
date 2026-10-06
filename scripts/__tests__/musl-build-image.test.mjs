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

/** The build steps need these; a Dockerfile that lost one would still build. */
const TOOLCHAIN = [
  'build-base',
  'cmake',
  'curl',
  'git',
  'linux-headers',
  'perl',
  'rustup',
]

/** Each `RUN apk add` in the Dockerfile, as its list of package arguments. */
function apkAdds(text) {
  // Join `\`-continued lines so one instruction is one string.
  const instructions = text.replace(/\\\n/g, ' ').split('\n')
  return instructions
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
    const froms = dockerfile
      .split('\n')
      .filter((line) => /^FROM\b/.test(line))
      .map((line) => line.replace(/^FROM\s+/, '').trim())
    // One stage: the preflights read `FROM` with `sed -n 's/^FROM //p'` and
    // run the smoke test in that image, so a second stage would hand them two.
    expect(froms).toHaveLength(1)
    expect(froms[0]).toMatch(PINNED)
  })

  it('pins every apk package to an exact version', () => {
    const adds = apkAdds(dockerfile)
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
    const names = apkAdds(dockerfile)
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

  it('name the base image digest nowhere, so the Dockerfile is its one home', () => {
    const copies = workflows
      .filter(({ text }) => /node:\d+-alpine@sha256:/.test(text))
      .map(({ relPath }) => relPath)
    expect(
      copies,
      `These workflows carry their own copy of the Alpine image digest. Dependabot moves the one in ${DOCKERFILE}, and a copy is left behind — read it from the Dockerfile as the preflights do.`,
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
  })

  it('builds the Dockerfile on a schedule and on every change to it', () => {
    const relPath = '.github/workflows/musl-build-image.yml'
    const wf = readWorkflow(relPath)
    const on = wf?.on ?? wf?.[true]
    expect(on?.schedule?.length ?? 0).toBeGreaterThan(0)
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
  })
})
