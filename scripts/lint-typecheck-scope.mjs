/**
 * A `typecheck` gate must compile SOURCE, and only source.
 *
 * TypeScript's default `exclude` is `["node_modules", "bower_components",
 * "jspm_packages"]` plus `outDir` — it does NOT cover `dist/`. So a tsconfig
 * with no `include`, no `exclude` and no `outDir` globs `**\/*`, which sweeps the
 * package's own build output into the program alongside its source.
 *
 * That makes a CI gate non-deterministic in a way that is invisible when it
 * passes. `turbo run typecheck --filter <pkg>` only builds the package's
 * DEPENDENCIES (`dependsOn: ["^build"]`), not the package itself, so whether
 * `dist/` exists during the gate depends on what an unrelated earlier CI step
 * happened to build transitively. Reorder the steps and the gate silently
 * compiles a different set of files. Locally, after a full build, it compiles a
 * different set again.
 *
 * `skipLibCheck` hides most of the consequences — a stale `.d.ts` importing a
 * deleted package still exits 0 — so this cannot be left to "CI is green".
 *
 * Fix by scoping the tsconfig: either an explicit `include` naming the source
 * roots, or an `exclude` listing `dist`. Note that specifying `exclude` REPLACES
 * the default list, so `node_modules` must be re-listed alongside `dist`.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

const REPO_ROOT = resolve(import.meta.dirname, '..')

// Roots holding workspace members, mirroring `pnpm-workspace.yaml`. Override
// with argv[2..] for tests / ad-hoc checks (each arg is a package directory).
//
// NESTED roots are listed separately because the walk below is one level deep,
// matching how pnpm globs `packages/*`. Three sets of packages sit a level
// further down and need their own entry here for the same reason they need one
// in `pnpm-workspace.yaml`:
//
//   packages/protect-ffi/platforms/*   the six per-platform binary packages
//   packages/eql/packages/*            @cipherstash/eql, from the EQL subtree
//   packages/protect-ffi/*             the live integration suite
//
// The last is spelled as its PARENT rather than as the member, because the walk
// takes roots and lists their children. That sweeps protect-ffi's non-package
// siblings (`crates`, `docs`, `src`, …) into the candidate list too; they carry
// no package.json / tsconfig.json pair, so the loop below skips them.
//
// Getting this wrong is silent in the direction that matters: a package outside
// the scan is never reported, which reads exactly like a package that passed.
// `packages/eql` itself is matched by the `packages` root and carries no
// package.json (the private workspace manifest was deleted with the import), so
// the loop skips it and only the nested member is checked.
const WORKSPACE_ROOTS = [
  'packages',
  'examples',
  'packages/protect-ffi',
  'packages/protect-ffi/platforms',
  'packages/eql/packages',
]

/** Every directory that looks like a workspace member. */
function discoverPackages() {
  const found = []
  for (const root of WORKSPACE_ROOTS) {
    const abs = resolve(REPO_ROOT, root)
    if (!existsSync(abs)) continue
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue
      found.push(join(abs, entry.name))
    }
  }
  const e2e = resolve(REPO_ROOT, 'e2e')
  if (existsSync(e2e)) found.push(e2e)
  return found
}

const targets = process.argv.slice(2).length
  ? process.argv.slice(2).map((t) => resolve(REPO_ROOT, t))
  : discoverPackages()

/**
 * Strip comments and trailing commas so `JSON.parse` accepts a tsconfig.
 *
 * Scans character by character tracking string state rather than pattern
 * matching: these tsconfigs map `"@/*": ["../stack/src/*"]`, and a regex for
 * block comments happily eats from the `/*` inside that key to the next `*\/`,
 * silently destroying the file it was meant to read.
 */
function readJsonc(path) {
  const raw = readFileSync(path, 'utf8')
  let out = ''
  let inString = false
  let escaped = false

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]

    if (inString) {
      out += ch
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === '"') inString = false
      continue
    }

    if (ch === '"') {
      inString = true
      out += ch
      continue
    }
    if (ch === '/' && raw[i + 1] === '/') {
      while (i < raw.length && raw[i] !== '\n') i++
      out += '\n'
      continue
    }
    if (ch === '/' && raw[i + 1] === '*') {
      i += 2
      while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/')) i++
      i++
      continue
    }
    out += ch
  }

  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'))
}

const offenders = []

for (const pkgDir of targets) {
  const pkgJsonPath = join(pkgDir, 'package.json')
  const tsconfigPath = join(pkgDir, 'tsconfig.json')
  if (!existsSync(pkgJsonPath) || !existsSync(tsconfigPath)) continue

  let pkgJson
  let tsconfig
  try {
    pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf8'))
    tsconfig = readJsonc(tsconfigPath)
  } catch (err) {
    offenders.push(
      `${relative(REPO_ROOT, tsconfigPath)}: could not be parsed — ${err.message}`,
    )
    continue
  }

  // Only packages wired as a gate. A tsconfig nothing runs is an editor
  // setting, not a CI contract.
  const scripts = pkgJson.scripts ?? {}
  const gate =
    scripts.typecheck ??
    (scripts.build === 'tsc --noEmit' ? scripts.build : undefined)
  if (gate === undefined) continue

  // An explicit `include` scopes the program by itself.
  if (Array.isArray(tsconfig.include) && tsconfig.include.length > 0) continue

  // Otherwise `exclude` has to carry it. `outDir` also excludes by default, but
  // these gates all set `noEmit`, so relying on it would be a trap.
  const exclude = Array.isArray(tsconfig.exclude) ? tsconfig.exclude : []
  const excludesDist = exclude.some(
    (e) => typeof e === 'string' && /(^|\/)dist(\/|$|\*)/.test(e),
  )
  if (excludesDist) continue

  offenders.push(
    `${relative(REPO_ROOT, tsconfigPath)}: \`${pkgJson.name}\` runs a typecheck gate ` +
      `(\`${gate}\`) but the tsconfig declares neither an \`include\` nor an ` +
      '`exclude` covering `dist`, so the gate compiles its own build output',
  )
}

if (offenders.length > 0) {
  console.error(
    `Found ${offenders.length} typecheck gate(s) that compile build output as well as source:\n`,
  )
  for (const o of offenders) console.error(`  ${o}`)
  console.error(
    "\nTypeScript's default `exclude` does not cover `dist/`, so a tsconfig with\n" +
      "no `include` globs `**/*` and sweeps the package's own emitted `.d.ts`\n" +
      'and `.js` into the gate. Whether `dist/` exists during CI depends on what\n' +
      'an earlier, unrelated step built transitively — so the gate compiles a\n' +
      'different program in CI than it does locally, and silently changes if the\n' +
      'steps are reordered.\n\n' +
      'Add to the tsconfig:\n\n' +
      '  "exclude": ["dist", "node_modules"]\n\n' +
      '(`exclude` REPLACES the default list, so `node_modules` must be re-listed.)\n' +
      'Or give it an explicit `include` naming the source roots, as `e2e` and\n' +
      '`examples/prisma` do.',
  )
  process.exit(1)
}
