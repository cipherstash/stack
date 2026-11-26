import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { REPO_ROOT } from './repo-root.mjs'

/**
 * Reading `.github/workflows`, for the guards that assert things about CI.
 *
 * Several of those guards are DISCOVERY tests — they scan the directory rather
 * than iterate a list, so a workflow added tomorrow is held to the same bar
 * without anyone remembering to register it. That design only works if every
 * guard discovers the same set, and before this module they each rolled their
 * own: three byte-for-byte copies of `workflowFiles` and `readWorkflow`, plus
 * two more spelled differently (`discoverWorkflows`, a bare `WORKFLOWS` const)
 * and a `readYaml` that was `readWorkflow` under another name. Copies of a
 * discovery helper are the worst kind to let drift, because a copy that finds
 * nothing does not fail — it passes, having checked nothing.
 *
 * Extracted alongside `read-jsonc.mjs`, for the same reason it was.
 */

/**
 * Where GitHub reads workflows from — and the only place it reads them from. A
 * workflow file deposited under a package's own `.github/workflows` is inert,
 * which is the failure `languages/typescript/packages/protect-ffi/src/integrationSuiteCi.test.ts`
 * exists to catch.
 */
export const WORKFLOW_DIR = '.github/workflows'

/**
 * Every workflow, as a repo-relative path, sorted.
 *
 * Both extensions: GitHub accepts `.yml` and `.yaml`, so a guard that filtered
 * on one of them would silently stop covering a workflow the day someone spelt
 * it the other way.
 */
export function workflowFiles() {
  return readdirSync(join(REPO_ROOT, WORKFLOW_DIR))
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => `${WORKFLOW_DIR}/${name}`)
    .sort()
}

/**
 * Parse one repo-relative YAML file from the workflow graph — a workflow, or a
 * composite action manifest that a workflow reaches through `uses: ./...`.
 * `flattenSteps` below follows those `uses:` edges and needs to parse both
 * kinds with the same reader.
 *
 * Note for callers: `on:` parses as the boolean `true` under YAML 1.1 (the
 * "Norway problem"), so read triggers as `wf.on ?? wf[true]`.
 */
export function readWorkflow(relPath) {
  return yaml.load(readFileSync(join(REPO_ROOT, relPath), 'utf8'))
}

export function usesOf(step) {
  return typeof step?.uses === 'string' ? step.uses.trim() || null : null
}

const LOCAL_USES = /^\.{1,2}\//

function stepLabel(step, index) {
  return step?.name || usesOf(step) || `step #${index + 1}`
}

/**
 * Flattens a step list, splicing a local composite action's own steps in at the
 * position of the `uses:` that reaches it. The result is the sequence GitHub
 * actually executes, which is the only sequence in which "before" means
 * anything.
 *
 * `resolveComposite` is injected so a guard can exercise its checker against
 * synthetic composites without writing fixture files — an in-repo scan is not
 * a test of the traversal, it is a test of the repo. The repo's own resolver is
 * `resolveRepoComposite`.
 *
 * `visited` breaks the `A uses B uses A` cycle. Scoped per job, matching
 * `lint-no-workflow-caching.mjs`: a composite shared by two jobs is flattened
 * into each.
 */
export function flattenSteps(
  steps,
  resolveComposite,
  trail = '',
  visited = new Set(),
) {
  const flat = []
  const unresolved = []

  ;(Array.isArray(steps) ? steps : []).forEach((step, index) => {
    const label = `${trail}${stepLabel(step, index)}`
    const uses = usesOf(step)

    if (uses === null || !LOCAL_USES.test(uses)) {
      flat.push({ step, label })
      return
    }

    const composite = resolveComposite(uses)
    if (composite === null) {
      // Fail closed. A local `uses:` pointing at nothing fails the job on
      // GitHub anyway; passing it here would make "rename the action" a way to
      // leave a check with nothing to read.
      unresolved.push(`${label}: \`uses: ${uses}\` — no action manifest there`)
      flat.push({ step, label })
      return
    }
    if (visited.has(composite.id)) return
    visited.add(composite.id)

    const nested = flattenSteps(
      composite.steps,
      resolveComposite,
      `${label} -> ${composite.id} step "`,
      visited,
    )
    for (const entry of nested.flat) {
      flat.push({ step: entry.step, label: `${entry.label}"` })
    }
    unresolved.push(...nested.unresolved)
  })

  return { flat, unresolved }
}

/**
 * GitHub resolves `uses: ./x` against the checkout root, not the calling file.
 * Both manifest spellings are valid, so probing only `action.yml` would stop
 * the traversal dead at a composite that used the other one.
 */
export function resolveRepoComposite(usesPath) {
  const dir = usesPath.replace(LOCAL_USES, '')
  for (const name of ['action.yml', 'action.yaml']) {
    const rel = `${dir}/${name}`
    if (existsSync(join(REPO_ROOT, rel))) {
      const doc = readWorkflow(rel)
      return { id: rel, steps: doc?.runs?.steps ?? [] }
    }
  }
  return null
}
