/**
 * Does EQL still owe the GitHub assets for the version in the tree?
 *
 * `release.yml`'s `eql-sql`, `eql-docs` and `eql-image` build the `eql-<version>`
 * tag and release with the SQL bundle, the docs bundle and the `postgres-eql`
 * image. They ran when a step after `changeset publish` reported it had just
 * published `@cipherstash/eql`. A failed `changeset publish` never reached that
 * step, even when it HAD published EQL, and a re-run found nothing left to
 * publish. That is why EQL 3.0.6 is on npm with no tag, release or image.
 *
 * So the answer comes from state that outlives a run: the assets are owed when
 * npm carries the tree's version and the `eql-<version>` tag does not exist.
 * This run's own publish also counts, because npm lists a new version minutes
 * after accepting it.
 *
 * THE ASSETS ARE BUILT AT THE COMMIT NPM'S TARBALL CAME FROM. changesets/action
 * pushes `@cipherstash/eql@<version>` at the commit it published, so a run
 * repairing an older release builds that release's source rather than main's.
 * With no such tag, only this run's publish can say which commit it was; a
 * version on npm with neither is refused rather than guessed.
 */
import { execFileSync } from 'node:child_process'
import { appendFileSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { EQL_PACKAGE, eqlPipelineArmed } from './eql-pipeline-armed.mjs'
import { npmVersions } from './release-gate.mjs'

const REPO_ROOT = resolve(import.meta.dirname, '..')

/** Two levels down: the subtree root carries no package.json. */
export const EQL_MANIFEST = 'packages/eql/packages/eql/package.json'

/**
 * The versions this may name. It ends up in a tag, a release name and a
 * `gh workflow run -f` argument, so anything else is refused here.
 */
const VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/

export const assetTag = (version) => `eql-${version}`
export const changesetsTag = (version) => `${EQL_PACKAGE}@${version}`

/** changesets/action's `publishedPackages`: a JSON array, or empty. */
export function parsePublished(text) {
  if (!text) return []
  const parsed = JSON.parse(text)
  if (!Array.isArray(parsed)) {
    throw new Error(`publishedPackages is not an array: ${text}`)
  }
  return parsed
}

/**
 * `npmHas(version)` and `tagCommit(tag)` are asked lazily, in the order
 * below, so a version that is already tagged costs no registry call.
 *
 * `armed` first: while EQL is a frozen publisher its versions reach npm from
 * another repository, with no changesets tag here, and the refusal below would
 * fail every push to main.
 */
export function eqlAssets({
  version,
  published,
  npmHas,
  tagCommit,
  headSha,
  armed = eqlPipelineArmed(),
}) {
  if (!VERSION.test(version)) {
    throw new Error(
      `${EQL_MANIFEST} carries version \`${version}\`, which is not X.Y.Z or X.Y.Z-pre`,
    )
  }
  const prerelease = version.includes('-')
  const none = (reason) => ({
    needed: false,
    version,
    prerelease,
    ref: '',
    reason,
  })

  if (!armed) return none('the EQL release line is not armed')

  const tagged = tagCommit(assetTag(version))
  if (tagged) {
    return none(`${assetTag(version)} already exists at ${tagged}`)
  }

  const thisRun = published.some(
    (p) => p.name === EQL_PACKAGE && p.version === version,
  )
  if (!thisRun && !npmHas(version)) {
    return none(`${EQL_PACKAGE}@${version} is not on npm`)
  }

  const publishedAt = tagCommit(changesetsTag(version))
  const ref = publishedAt ?? (thisRun ? headSha : null)
  if (!ref) {
    throw new Error(
      `${EQL_PACKAGE}@${version} is on npm and ${assetTag(version)} does not exist, ` +
        `but no ${changesetsTag(version)} tag says which commit published it. Build the ` +
        'assets by hand from that commit, or push the tag there.',
    )
  }
  return {
    needed: true,
    version,
    prerelease,
    ref,
    reason: `${EQL_PACKAGE}@${version} is ${thisRun ? 'published by this run' : 'on npm'} and ${assetTag(version)} does not exist; building at ${ref}`,
  }
}

function gh(...args) {
  return JSON.parse(execFileSync('gh', ['api', ...args], { encoding: 'utf8' }))
}

/**
 * The commit a tag names, or `null` when there is no such tag. Errors throw:
 * reading a failed lookup as "no tag" would build a second release.
 *
 * `matching-refs`, not `git/ref`: see `publish-ffi` in release.yml. An
 * annotated tag points at a tag object, which names the commit.
 */
export function tagCommitVia(repo, call = gh) {
  return (tag) => {
    const ref = call(`repos/${repo}/git/matching-refs/tags/${tag}`).find(
      (entry) => entry.ref === `refs/tags/${tag}`,
    )
    if (!ref) return null
    let object = ref.object
    for (let depth = 0; object.type === 'tag'; depth++) {
      if (depth === 5) throw new Error(`${tag} nests tag objects too deeply`)
      object = call(`repos/${repo}/git/tags/${object.sha}`).object
    }
    return object.sha
  }
}

function required(name) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is not set`)
  return value
}

function main() {
  const { version } = JSON.parse(
    readFileSync(join(REPO_ROOT, EQL_MANIFEST), 'utf8'),
  )
  const result = eqlAssets({
    version,
    published: parsePublished(process.env.PUBLISHED_PACKAGES),
    npmHas: (v) => [npmVersions(EQL_PACKAGE) ?? []].flat().includes(v),
    tagCommit: tagCommitVia(required('REPO')),
    headSha: required('GITHUB_SHA'),
  })

  console.log(result.reason)
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `needed=${result.needed}\nversion=${result.version}\n` +
        `prerelease=${result.prerelease}\nref=${result.ref}\n`,
    )
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main()
  } catch (err) {
    console.error(`::error::${err.message}`)
    process.exit(1)
  }
}
