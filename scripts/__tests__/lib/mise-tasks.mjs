// Reads mise task definitions without a TOML parser: adding one is an audit
// decision in this repo, and the guards need only headers, `depends` and
// body text.

export const parseStringArray = (inner) =>
  [...inner.matchAll(/"([^"]+)"|'([^']+)'/g)].map((m) => m[1] ?? m[2])

export function parseIncludes(miseText) {
  const section = /^\[task_config\][^\n]*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(
    miseText,
  )
  const array = /^includes\s*=\s*\[([^\]]*)\]/m.exec(section?.[1] ?? '')
  return array ? parseStringArray(array[1]) : []
}

/**
 * The two dialects must not be merged. In `mise.toml` a task is
 * `[tasks."name"]`, and a bare `[tools]` or `[env]` is configuration. In a
 * file named by `includes`, every top-level table is a task, `["name"]`, and
 * mise rejects `[tasks."name"]` there. Pass `bareTables: true` for such a file.
 */
export function parseTomlTasks(text, { bareTables }) {
  const header = bareTables
    ? /^\[(?:"([^"]+)"|([\w:.-]+))\]/
    : /^\[tasks\.(?:"([^"]+)"|([\w:.-]+))\]/
  return text
    .split(/^(?=\[)/m)
    .map((block) => ({ match: header.exec(block), block }))
    .filter(({ match }) => match)
    .map(({ match, block }) => ({ name: match[1] ?? match[2], block }))
}

// Memoised: eql-suite-ci.test.mjs re-runs its reachability walk once per
// workflow, tens of thousands of calls over ~100 bodies, and without the cache
// it flakes against vitest's 5s timeout.
const strippedBodies = new Map()
export function stripCommentLines(text) {
  let stripped = strippedBodies.get(text)
  if (stripped === undefined) {
    stripped = text.replace(/^[ \t]*#.*$/gm, '')
    strippedBodies.set(text, stripped)
  }
  return stripped
}
