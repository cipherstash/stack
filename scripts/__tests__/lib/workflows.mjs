import { readdirSync, readFileSync } from 'node:fs'
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
 * which is the failure `packages/protect-ffi/src/integrationSuiteCi.test.ts`
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
 * `workflow-node-gyp.test.mjs` follows those `uses:` edges and needs to parse
 * both kinds with the same reader.
 *
 * Note for callers: `on:` parses as the boolean `true` under YAML 1.1 (the
 * "Norway problem"), so read triggers as `wf.on ?? wf[true]`.
 */
export function readWorkflow(relPath) {
  return yaml.load(readFileSync(join(REPO_ROOT, relPath), 'utf8'))
}
