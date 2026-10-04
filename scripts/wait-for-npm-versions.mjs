/**
 * Wait until npm lists every version the native publish jobs just published.
 *
 * `release.yml`'s `publish-ffi` and `publish-auth` publish with `npm publish`,
 * then the `release` job runs `changeset publish`, which publishes every
 * version `npm info <name>` does not list. npm accepts a publish minutes
 * before it lists it, so changesets publishes the native packages again —
 * from the workspace, with `restricted` access — and npm refuses with E402.
 * That failed the `release` job for `@cipherstash/protect-ffi` 0.33.0 and
 * `@cipherstash/auth` 0.44.1 on 2 October 2026. This polls the same `versions`
 * list, through the same npm, before changesets asks.
 *
 * A lookup error is retried rather than thrown: a 404 is a first publish npm
 * does not list yet, and a registry error says nothing about the publish. The
 * deadline bounds both. A timeout fails the step BEFORE `changeset publish`,
 * so nothing is published, and a re-run waits again.
 */
import process from 'node:process'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { npmVersions } from './release-gate.mjs'

/** npm says "a few minutes". The two failed runs had waited 1 to 2. */
export const DEFAULT_TIMEOUT_SECONDS = 900
export const DEFAULT_INTERVAL_SECONDS = 15

/**
 * Space-separated `name@version` entries, as the publish jobs export them. A
 * skipped job exports an empty string. The LAST `@` splits, so a scope survives.
 */
export function parseSpecs(text) {
  return String(text ?? '')
    .split(/\s+/)
    .filter(Boolean)
    .map((entry) => {
      const at = entry.lastIndexOf('@')
      const [name, version] = [entry.slice(0, at), entry.slice(at + 1)]
      if (at <= 0 || !version) {
        throw new Error(`\`${entry}\` is not a name@version entry`)
      }
      return { name, version }
    })
}

const label = ({ name, version }) => `${name}@${version}`

/** `lookup` answers like `npmVersions`: the versions, or `null` for a 404. */
export async function waitForVersions(
  specs,
  {
    lookup = npmVersions,
    timeoutMs = DEFAULT_TIMEOUT_SECONDS * 1000,
    intervalMs = DEFAULT_INTERVAL_SECONDS * 1000,
    now = Date.now,
    wait = sleep,
    log = console.log,
  } = {},
) {
  const deadline = now() + timeoutMs
  const lastError = new Map()
  let missing = specs

  for (;;) {
    missing = missing.filter((spec) => {
      try {
        const listed = [lookup(spec.name) ?? []].flat().includes(spec.version)
        lastError.delete(label(spec))
        if (listed) log(`${label(spec)} is listed on npm`)
        return !listed
      } catch (err) {
        lastError.set(label(spec), err.message)
        return true
      }
    })
    if (missing.length === 0) return

    if (now() >= deadline) {
      const detail = missing.map((spec) => {
        const error = lastError.get(label(spec))
        return error ? `${label(spec)} (${error})` : label(spec)
      })
      throw new Error(
        `npm did not list these within ${Math.round(timeoutMs / 1000)}s: ${detail.join(', ')}. ` +
          '`changeset publish` would publish them again and fail. Re-run the job once ' +
          '`npm view <name> versions` lists them.',
      )
    }
    log(`waiting for npm to list ${missing.map(label).join(', ')}`)
    await wait(intervalMs)
  }
}

function seconds(name, fallback) {
  const raw = process.env[name]
  if (raw === undefined || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be a number of seconds, not \`${raw}\``)
  }
  return value
}

async function main() {
  const specs = [
    ...parseSpecs(process.env.FFI_PUBLISHED),
    ...parseSpecs(process.env.AUTH_PUBLISHED),
  ]
  if (specs.length === 0) {
    console.log('publish-ffi and publish-auth published nothing; no wait.')
    return
  }
  // The workflow sets neither; they exist for the process tests.
  await waitForVersions(specs, {
    timeoutMs:
      seconds('NPM_WAIT_TIMEOUT_SECONDS', DEFAULT_TIMEOUT_SECONDS) * 1000,
    intervalMs:
      seconds('NPM_WAIT_INTERVAL_SECONDS', DEFAULT_INTERVAL_SECONDS) * 1000,
  })
  console.log(`npm lists all ${specs.length}.`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(`::error::${err.message}`)
    process.exit(1)
  })
}
