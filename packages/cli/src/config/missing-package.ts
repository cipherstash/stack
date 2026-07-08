// Turn a raw jiti/Node `Cannot find module 'stash'` into actionable guidance.
// A `stash.config.ts` `import`s `stash`; the encryption client it points at
// `import`s `@cipherstash/stack` (incl. subpaths like `@cipherstash/stack/schema`).
// Both resolve only once those are project dependencies — via `stash init`, or a
// manual install — so a bare project (e.g. `npx stash eql install` before init)
// otherwise crashes with a stack trace. See #579.

import {
  combinedInstallCommands,
  detectPackageManager,
  runnerCommand,
} from '../commands/init/utils.js'
import { messages } from '../messages.js'
import { isModuleNotFound, moduleNotFoundSpecifier } from '../module-error.js'

const CLI_PACKAGE = 'stash'
const STACK_PACKAGE = '@cipherstash/stack'

/** Reduce a specifier (`@cipherstash/stack/schema`, `stash/foo`) to its package name. */
function packageNameOf(specifier: string): string {
  const parts = specifier.split('/')
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
}

/**
 * If `error` is a module-resolution failure for one of the CipherStash packages
 * a config (`stash`) or its encryption client (`@cipherstash/stack`, incl.
 * subpaths) imports, return that package name. Returns `undefined` for any other
 * error, so the caller can surface it raw.
 */
export function missingCipherStashPackage(error: unknown): string | undefined {
  if (!isModuleNotFound(error)) return undefined
  const specifier = moduleNotFoundSpecifier(error)
  if (!specifier) return undefined
  const pkg = packageNameOf(specifier)
  return pkg === CLI_PACKAGE || pkg === STACK_PACKAGE ? pkg : undefined
}

/**
 * Print actionable guidance for a missing CipherStash package and exit, instead
 * of leaking jiti's raw stack trace. Shared by every command that jiti-loads the
 * config or the encryption client.
 */
export function reportMissingCipherStashPackage(pkg: string): never {
  const pm = detectPackageManager()
  const stash = runnerCommand(pm, 'stash')
  const install = combinedInstallCommands(pm, [STACK_PACKAGE], [CLI_PACKAGE])
  console.error(
    `Error: ${messages.db.missingCipherStashPackage(pkg, install.join('\n  '), stash)}\n`,
  )
  process.exit(1)
}
