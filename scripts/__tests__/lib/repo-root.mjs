import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * The repository root, resolved from this file's own location.
 *
 * Every guard in `scripts/__tests__/` asserts against real repo files —
 * workflows, manifests, source trees, `turbo.json` — so every one of them needs
 * this, and thirteen of them declared it byte-for-byte identically before it
 * was extracted. One copy is one place to fix if the directory ever moves; the
 * other twelve would have been found one failing suite at a time, which is not
 * a plan.
 *
 * Note the depth. This lives one directory deeper than the test files that used
 * to declare it, so it climbs `../../../..` where they climbed `../../..`.
 * `resolve` treats the file path as the starting segment, hence the extra level
 * that looks off by one and is not.
 */
export const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../../..')
