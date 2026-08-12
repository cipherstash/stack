import { mkdtempSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

// `doctor` sorts a probe failure into four arms, and only one of them — the
// missing platform binary — had coverage (`doctor-missing-binary.e2e.test.ts`).
// These are the two a user reaches by doing nothing wrong:
//
//   * `@cipherstash/stack` absent. It is an OPTIONAL PEER, so `npx stash
//     doctor` in a project that has not run `stash init` lands here. Must read
//     as recoverable, not as a failure.
//   * `@cipherstash/stack` installed but older than the `./diagnostics`
//     subpath — every version inside the `>=1.0.0-rc.0` peer range that the CLI
//     itself permits. Unclassified, this reaches doctor's `else`, is rethrown,
//     and surfaces as the launcher's bare `Fatal error`.
//
// Both errors are raised by NODE'S OWN resolver, never hand-built: a
// `module.registerHooks` resolve hook re-points the specifier and lets
// resolution fail on its own terms. A fixture that pasted the message and code
// on by hand would keep passing if Node ever changed either, which is the whole
// risk being covered here.

/** Mirrors the probe labels in `src/commands/doctor/index.ts`. */
const ENCRYPTION_LABEL = 'Encryption engine (@cipherstash/stack → protect-ffi)'
const AUTH_LABEL = 'Auth (@cipherstash/auth)'

interface Unresolve {
  /** The bare specifier to divert. */
  specifier: string
  /**
   * Resolve this instead — a subpath the package really does not publish, so
   * Node raises its own `ERR_PACKAGE_PATH_NOT_EXPORTED`. Omit to keep the
   * specifier and move the IMPORTER to an empty directory instead, which is how
   * an absent package is staged: same specifier, no `node_modules` chain to
   * find it in, so Node raises `ERR_MODULE_NOT_FOUND` naming the base package.
   */
  redirectTo?: string
}

/**
 * Writes a hook module that makes `specifier` unresolvable in the spawned CLI,
 * and returns the `NODE_OPTIONS` value that loads it.
 *
 * A resolve hook rather than the `Module._load` patch its sibling suite uses:
 * the probe is an `await import()` of a real ESM package, so it never reaches
 * the CJS loader. `registerHooks` is synchronous and in-process, so the error
 * propagates out of the dynamic import exactly as an unhooked failure would.
 */
function unresolve({ specifier, redirectTo }: Unresolve): string {
  const dir = mkdtempSync(join(tmpdir(), 'stash-doctor-probe-'))
  const hook = join(dir, 'unresolve.mjs')
  // Importer inside the fresh temp dir. It is never written — resolution fails
  // before anything is read — it only has to sit somewhere with no
  // `node_modules` above it holding the package.
  const emptyParent = pathToFileURL(join(dir, 'importer.mjs')).href
  writeFileSync(
    hook,
    `import { registerHooks } from 'node:module'

const SPECIFIER = ${JSON.stringify(specifier)}
const REDIRECT = ${JSON.stringify(redirectTo ?? null)}
const EMPTY_PARENT = ${JSON.stringify(emptyParent)}

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier !== SPECIFIER) return nextResolve(specifier, context)
    if (REDIRECT) return nextResolve(REDIRECT, context)
    return nextResolve(specifier, { ...context, parentURL: EMPTY_PARENT })
  },
})
`,
  )
  // Quoted: Node splits NODE_OPTIONS on whitespace unless a value is wrapped in
  // double quotes, and the hook sits under a tmpdir this file did not choose.
  return [process.env.NODE_OPTIONS, `--import "${pathToFileURL(hook).href}"`]
    .filter(Boolean)
    .join(' ')
}

// `module.registerHooks` landed in Node 22.15, and `engines` only asks for
// `>=22`. Skipped rather than failed on an older runtime: the child would die
// in the preload with a TypeError that reads as a broken CLI. CI runs 22 and 24
// at their latest patch, so this never skips there.
const hooksAvailable = typeof registerHooks === 'function'

describe.skipIf(!hooksAvailable)('stash doctor — probe classification', () => {
  it('reports an absent @cipherstash/stack as recoverable, not a failure', async () => {
    // The `npx stash doctor` path in a project that has not run `stash init`.
    // Node names the BASE package for a missing subpath of an absent package,
    // which is why the probe imports `./diagnostics` but classifies against
    // `@cipherstash/stack`.
    const r = render(['doctor'], {
      env: {
        NODE_OPTIONS: unresolve({
          specifier: '@cipherstash/stack/diagnostics',
        }),
      },
      cols: 140,
    })
    const { exitCode } = await r.exit

    expect(exitCode, r.output).toBe(0)
    expect(r.output).toContain(
      `${ENCRYPTION_LABEL} — ${messages.doctor.notInstalledOptional}`,
    )
    expect(r.output).toContain(messages.doctor.allChecksPassed)
    expect(r.output).not.toContain('Fatal error')
    // The optional package's absence must not be dressed up as a missing
    // binary — that would send the user to a reinstall for a package they
    // simply have not installed yet.
    expect(r.output).not.toContain(messages.doctor.nativeBinaryMissing)
  })

  it('warns, and does not claim every check passed, when a probe cannot run', async () => {
    // An `@cipherstash/stack` older than the `./diagnostics` subpath. Nothing
    // is known to be wrong with it — the install may be perfectly healthy — so
    // this is not a failure and must not exit non-zero. It is also not a pass:
    // the check did not run, and an outro saying every check passed would be
    // the one line of output that is untrue.
    const r = render(['doctor'], {
      env: {
        NODE_OPTIONS: unresolve({
          specifier: '@cipherstash/stack/diagnostics',
          redirectTo: '@cipherstash/stack/no-such-subpath',
        }),
      },
      cols: 140,
    })
    const { exitCode } = await r.exit

    expect(exitCode, r.output).toBe(0)
    expect(r.output).toContain(
      `${ENCRYPTION_LABEL} — ${messages.doctor.cannotProbe}`,
    )
    expect(r.output).toContain(messages.doctor.checksIncomplete)
    expect(r.output).not.toContain(messages.doctor.allChecksPassed)
    // The arm exists to keep this error out of doctor's `else`, where it is
    // rethrown and the launcher prints it raw.
    expect(r.output).not.toContain('Fatal error')
  })

  it('fails on an absent required package', async () => {
    // `@cipherstash/auth` is a hard dependency, so absence is a broken install
    // — the row must go red and the run must exit non-zero. Non-optional is a
    // separate branch from the case above and would otherwise be asserted
    // nowhere.
    const r = render(['doctor'], {
      env: { NODE_OPTIONS: unresolve({ specifier: '@cipherstash/auth' }) },
      cols: 140,
    })
    const { exitCode } = await r.exit

    expect(exitCode, r.output).toBe(1)
    expect(r.output).toContain(
      `${AUTH_LABEL} — ${messages.doctor.notInstalled}`,
    )
    expect(r.output).toContain(messages.doctor.problemsFound)
    expect(r.output).not.toContain('Fatal error')
  })
})
