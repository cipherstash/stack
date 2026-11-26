/**
 * protect-ffi's `test` must not rewrite `lib/` while other packages read it.
 *
 * Root `pnpm test` runs `turbo test` over every package at once, in one
 * checkout. `lib/` is protect-ffi's build output and its `main`: the builds of
 * `@cipherstash/stack`, `stack-drizzle` and `stack-supabase` read
 * `lib/*.d.*` from it. `test:typecheck` used to start with a plain `tsc`,
 * which writes every file in `lib/` again. While tsc writes a file, the file
 * is briefly empty. A build that read `lib/types.d.ts` at that moment saw no
 * exports, and tsup failed with TS2305 ("has no exported member
 * 'AuthStrategy'"). That failed Test JS on pull request #1845.
 *
 * Two rules close the race, and this file checks both:
 *
 * 1. No `tsc` reachable from protect-ffi's `test` script emits files. A
 *    typecheck needs no output, so `--noEmit` (or a tsconfig with
 *    `noEmit: true`) costs nothing.
 * 2. turbo runs `@cipherstash/protect-ffi#test` after its own `build`. The
 *    unit tests in `nativeLoading.test.ts` read the emitted `lib/index.cjs`,
 *    and rule 1 means the test no longer writes it. Declaring the edge also
 *    puts every reader of `lib/` after the one write turbo makes to it.
 *
 * The failure this guards against is timing-dependent. It showed up on a
 * small share of runs, so a green CI run is no evidence the race is gone.
 */

import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { readJsonc } from './lib/read-jsonc.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

const PACKAGE_DIR = join(REPO_ROOT, 'languages/typescript/packages/protect-ffi')
const PACKAGE_NAME = '@cipherstash/protect-ffi'
const manifest = JSON.parse(
  readFileSync(join(PACKAGE_DIR, 'package.json'), 'utf8'),
)
const scripts = manifest.scripts

/**
 * Script names reachable from `root`, following `pnpm run` / `npm run` and the
 * `pre` / `post` hooks pnpm runs without being asked. The same walk as
 * `reachableFrom` in protect-ffi's `src/lintWiring.test.ts`.
 */
function reachableFrom(root) {
  const seen = new Set()
  const queue = [root]
  while (queue.length > 0) {
    const name = queue.pop()
    if (seen.has(name)) continue
    seen.add(name)
    const body = scripts[name]
    if (body === undefined) continue
    queue.push(`pre${name}`, `post${name}`)
    for (const match of body.matchAll(/(?:pnpm|npm) run ([\w:-]+)/g)) {
      queue.push(match[1])
    }
  }
  return seen
}

/**
 * Every `tsc` command in a script body, as its argument list. A command ends
 * at a shell operator or a redirect.
 */
function tscCommands(body) {
  const commands = []
  for (const segment of body.split(/&&|\|\||;|\||>/)) {
    const words = segment.trim().split(/\s+/)
    const at = words.indexOf('tsc')
    if (at !== -1) commands.push(words.slice(at + 1))
  }
  return commands
}

/**
 * The `noEmit` a tsconfig ends up with, following `extends`. A relative
 * `extends` is a path; any other is resolved like a package, from the
 * directory of the config that names it.
 */
function effectiveNoEmit(configPath) {
  const config = JSON.parse(readFileSync(configPath, 'utf8'))
  const own = config.compilerOptions?.noEmit
  if (own !== undefined) return own
  if (typeof config.extends !== 'string') return false
  const parent = config.extends.startsWith('.')
    ? resolve(dirname(configPath), config.extends)
    : createRequire(configPath).resolve(config.extends)
  return effectiveNoEmit(parent)
}

/** Whether a `tsc` with these arguments, run from the package, writes files. */
function emits(args) {
  if (args.includes('-b') || args.includes('--build')) return true
  const noEmitAt = args.indexOf('--noEmit')
  if (noEmitAt !== -1 && args[noEmitAt + 1] !== 'false') return false
  const projectAt = args.findIndex((a) => a === '-p' || a === '--project')
  const project = projectAt === -1 ? '.' : args[projectAt + 1]
  const configPath = project.endsWith('.json')
    ? join(PACKAGE_DIR, project)
    : join(PACKAGE_DIR, project, 'tsconfig.json')
  return !effectiveNoEmit(configPath)
}

describe('protect-ffi test does not rewrite lib/ during turbo test', () => {
  it('runs no emitting tsc from the test script', () => {
    const found = [...reachableFrom('test')].flatMap((name) =>
      tscCommands(scripts[name] ?? '').map((args) => ({ name, args })),
    )

    // Without a tsc on the path, the assertion below checks nothing.
    expect(
      found.length,
      'No tsc command is reachable from protect-ffi `test`, so this check reads nothing.',
    ).toBeGreaterThan(0)

    const emitting = found
      .filter(({ args }) => emits(args))
      .map(({ name, args }) => `${name}: tsc ${args.join(' ')}`.trim())
    expect(
      emitting,
      `These tsc commands run from protect-ffi \`test\` and write files into lib/. turbo runs other packages' builds at the same time, and they read lib/*.d.* while tsc rewrites it. Add --noEmit, or use a tsconfig with "noEmit": true.`,
    ).toEqual([])
  })

  it('runs protect-ffi test after its own build in turbo', () => {
    const turbo = readJsonc(join(REPO_ROOT, 'turbo.json'))
    const task = turbo.tasks[`${PACKAGE_NAME}#test`]

    expect(
      task,
      `turbo.json has no "${PACKAGE_NAME}#test" task, so protect-ffi's test uses the generic "test" task, which does not wait for protect-ffi's own build. nativeLoading.test.ts reads lib/index.cjs, which only build writes.`,
    ).toBeDefined()
    expect(task.dependsOn).toEqual(expect.arrayContaining(['build', '^build']))
  })

  it('keeps the settings of the generic test task', () => {
    // The package-specific task replaces the generic one for this package. A
    // setting left out here is lost for protect-ffi only, and nothing else
    // would notice.
    const turbo = readJsonc(join(REPO_ROOT, 'turbo.json'))
    const generic = turbo.tasks.test
    const specific = turbo.tasks[`${PACKAGE_NAME}#test`]
    expect(specific).toBeDefined()
    for (const key of Object.keys(generic)) {
      if (key === 'dependsOn') continue
      expect(specific[key], `"${PACKAGE_NAME}#test".${key}`).toEqual(
        generic[key],
      )
    }
  })
})
