/**
 * Build every guest the Go module embeds, into a directory the release
 * workflow uploads.
 *
 * Each guest's root mise task builds the release module, checks its host-import
 * surface (scripts/check-wasm-imports.py) and copies it into the module. This
 * runs those tasks and collects their output under `<out>/<path>`, so the
 * `publish` job of .github/workflows/release-golang.yml can compare two
 * builds. The list of guests is `GUESTS` in scripts/golang-release.mjs.
 *
 * Its own file because it is the only part of the release line that runs
 * mise: scripts/__tests__/workflow-mise-setup.test.mjs requires every job that
 * runs a script spawning mise to install it first, and `plan` should not.
 *
 *   node scripts/golang-release-build.mjs <out>
 */
import { execFileSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { GUESTS, sha256 } from './golang-release.mjs'

const REPO_ROOT = resolve(import.meta.dirname, '..')

/**
 * Run each guest's task and copy what it wrote into `out`. The file is
 * removed first, so a stale guest from an earlier build cannot stand in for
 * one the task did not write.
 */
export function buildGuests({
  out,
  root = REPO_ROOT,
  run = (task) =>
    execFileSync('mise', ['run', task], { cwd: root, stdio: 'inherit' }),
}) {
  return GUESTS.map(({ task, path }) => {
    const built = join(root, path)
    rmSync(built, { force: true })
    run(task)
    if (!existsSync(built)) {
      throw new Error(`\`mise run ${task}\` finished without writing ${path}`)
    }
    const target = join(out, path)
    mkdirSync(dirname(target), { recursive: true })
    copyFileSync(built, target)
    return { path, sha256: sha256(readFileSync(target)) }
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [out] = process.argv.slice(2)
    if (!out) throw new Error('usage: golang-release-build.mjs <out>')
    for (const { path, sha256: hash } of buildGuests({ out: resolve(out) })) {
      console.log(`${hash}  ${path}`)
    }
  } catch (err) {
    console.error(`::error::${err.message}`)
    process.exit(1)
  }
}
