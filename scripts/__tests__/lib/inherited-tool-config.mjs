import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { REPO_ROOT } from './repo-root.mjs'

/**
 * Tracked config files that mise and cargo read from the PARENT directories of
 * `dir`. Both tools search upward, so a job running them in `packages/eql`
 * reads the root `mise.toml` (its tools and its tasks, including every file
 * its `[task_config].includes` names) and the root `.cargo/config.toml`.
 *
 * Only `mise.toml` and `.cargo/config{,.toml}` are modelled: they are the
 * names this repository tracks. `mise.test.toml` loads only under
 * `MISE_ENV=test`, which no EQL job sets. A parent config of another name is
 * missed here, and the subtree-prefix check in `eql-suite-ci.test.mjs`
 * reports it as an offender the day a filter names it.
 */
export function inheritedToolConfig(dir) {
  const found = new Set()
  for (const parent of parentDirs(dir)) {
    const mise = join(parent, 'mise.toml')
    if (isTracked(mise)) {
      found.add(mise)
      for (const include of miseTaskIncludes(mise)) {
        for (const file of trackedAt(join(parent, include))) found.add(file)
      }
    }
    for (const cargo of ['.cargo/config.toml', '.cargo/config']) {
      const path = join(parent, cargo)
      if (isTracked(path)) found.add(path)
    }
  }
  return [...found].sort()
}

/** `packages/eql` -> `['packages', '.']`, nearest first. */
function parentDirs(dir) {
  const segments = dir.split('/').filter(Boolean)
  return segments.map((_, i) =>
    i === segments.length - 1 ? '.' : segments.slice(0, -1 - i).join('/'),
  )
}

function trackedAt(path) {
  return execFileSync('git', ['ls-files', '-z', '--', path], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
    .split('\0')
    .filter(Boolean)
}

const isTracked = (path) => trackedAt(path).includes(path)

/** Read by hand: the repository has no TOML reader. */
function miseTaskIncludes(relPath) {
  const text = readFileSync(join(REPO_ROOT, relPath), 'utf8')
  const table = /^\[task_config\]\s*\n([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(
    text,
  )?.[1]
  const list = /^\s*includes\s*=\s*\[([\s\S]*?)\]/m.exec(table ?? '')?.[1]
  return [...(list ?? '').matchAll(/"([^"]+)"|'([^']+)'/g)].map(
    (match) => match[1] ?? match[2],
  )
}
