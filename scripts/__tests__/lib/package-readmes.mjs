import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { workspacePackagePatterns } from '../../release-gate.mjs'
import { REPO_ROOT } from './repo-root.mjs'

/**
 * git pathspecs selecting every workspace package's `README.md`.
 *
 * ## Why this is derived rather than written down
 *
 * Both callers used to hardcode `:(glob)packages/*&#47;README.md`. `:(glob)` stops
 * `*` at a path separator — which is what makes `lib/*.ts` behave — and this
 * repo has TWO package roots nested deeper than one level:
 * `packages/protect-ffi/platforms/*` and `packages/eql/packages/*`. So the
 * hardcoded spec selected `packages/eql/README.md`, the 15 KB subtree root that
 * ships in no tarball, and never `packages/eql/packages/eql/README.md`, the
 * 518-byte file listed in that package's `files`. Same for the six per-platform
 * FFI packages. Seven published READMEs were unscanned and one unpublished one
 * was standing in for them, which is worse than scanning nothing: the guards
 * reported green over a set that did not contain what they were guarding.
 *
 * `pnpm-workspace.yaml` is the only place that knows how deep a package can be,
 * and it has to be edited to add one — so deriving from it means a third nested
 * root is covered the day it lands, rather than the day someone remembers this
 * file. Same reasoning, and the same parser, as `workspaceManifests()`.
 *
 * Narrowed to `packages/` deliberately: `examples/*` and `e2e` are workspace
 * members too, but they are private and their READMEs are not shipped to
 * anyone. The callers are guards on SHIPPED text.
 */
export function packageReadmePathspecs() {
  const patterns = workspacePackagePatterns(
    readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8'),
  ).filter((pattern) => pattern.startsWith('packages/'))

  if (patterns.length === 0) {
    throw new Error(
      'pnpm-workspace.yaml lists no `packages/` patterns — either the layout moved or this derivation broke. Failing rather than returning an empty pathspec list, which `git ls-files` would answer with the whole tree.',
    )
  }

  return patterns.map((pattern) => `:(glob)${pattern}/README.md`)
}
