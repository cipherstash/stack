import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

// `doctor` sorts a probe failure into four arms, and only one of them — the
// missing platform binary — had coverage (`doctor-missing-binary.e2e.test.ts`).
// These are the ones a user reaches by doing nothing wrong:
//
//   * `@cipherstash/stack` absent. It is an OPTIONAL PEER, so `npx stash
//     doctor` in a project that has not run `stash init` lands here. Must read
//     as recoverable, not as a failure.
//   * `@cipherstash/stack` installed but older than the `./diagnostics`
//     subpath — every version inside the `>=1.0.0-rc.0` peer range that the CLI
//     itself permits. Unclassified, this reaches doctor's `else`, is rethrown,
//     and surfaces as the launcher's bare `Fatal error`.
//   * The same error code from a probe that asks for no subpath, which cannot
//     mean "upgrade `@cipherstash/stack`" and must not be answered with it.
//
// Every error here is raised by NODE'S OWN resolver against a package layout
// this file builds — an absent package, an older one — never hand-built with
// the code and message pasted on. A fixture like that keeps passing when Node
// changes either, which is the whole risk being covered.

/** Mirrors the probe labels in `src/commands/doctor/index.ts`. */
const ENCRYPTION_LABEL = 'Encryption engine (@cipherstash/stack → protect-ffi)'
const AUTH_LABEL = 'Auth (@cipherstash/auth)'

interface Unresolve {
  /** The bare specifier to divert. */
  specifier: string
  /**
   * A package to install into the directory the specifier is re-resolved from,
   * carrying an `exports` map that does not answer what the probe asks for.
   * Omit and the directory stays empty, which is how an ABSENT package is
   * staged — no `node_modules` chain to find it in, so Node raises
   * `ERR_MODULE_NOT_FOUND` naming the base package.
   */
  installed?: { pkg: string; exports: Record<string, string> }
}

/**
 * Writes a hook module that re-resolves `specifier` against a directory this
 * test controls, and returns the `NODE_OPTIONS` value that loads it.
 *
 * Moving the IMPORTER rather than rewriting the specifier: the specifier the
 * CLI asks for has to reach Node's resolver unchanged, because what the
 * classifier keys on is which subpath of which package the error names. A
 * redirect to some other subpath produces the right error CODE against the
 * wrong subpath, which is a shape the real failure never has.
 *
 * A resolve hook rather than the `Module._load` patch its sibling suite uses:
 * the probe is an `await import()` of a real ESM package, so it never reaches
 * the CJS loader. `registerHooks` is synchronous and in-process, so the error
 * propagates out of the dynamic import exactly as an unhooked failure would.
 */
function unresolve({ specifier, installed }: Unresolve): string {
  const dir = mkdtempSync(join(tmpdir(), 'stash-doctor-probe-'))
  if (installed) {
    const pkgDir = join(dir, 'node_modules', ...installed.pkg.split('/'))
    mkdirSync(pkgDir, { recursive: true })
    writeFileSync(
      join(pkgDir, 'package.json'),
      JSON.stringify({
        name: installed.pkg,
        version: '0.0.0',
        exports: installed.exports,
      }),
    )
  }
  // The importer is never written — resolution fails before anything is read.
  // It only has to sit in this directory, so that what is (or is not) in the
  // `node_modules` beside it is what Node resolves against.
  const parent = pathToFileURL(join(dir, 'importer.mjs')).href
  const hook = join(dir, 'unresolve.mjs')
  writeFileSync(
    hook,
    `import { registerHooks } from 'node:module'

const SPECIFIER = ${JSON.stringify(specifier)}
const PARENT = ${JSON.stringify(parent)}

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier !== SPECIFIER) return nextResolve(specifier, context)
    return nextResolve(specifier, { ...context, parentURL: PARENT })
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
          // An `@cipherstash/stack` from before the subpath existed: present,
          // resolvable, and its `exports` answers `.` and nothing else.
          installed: {
            pkg: '@cipherstash/stack',
            exports: { '.': './dist/index.js' },
          },
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

  it('does not answer an exports failure elsewhere with stack-upgrade advice', async () => {
    // The too-old-to-probe arm keys on an error code, and every probe's failure
    // is offered to it. `ERR_PACKAGE_PATH_NOT_EXPORTED` can come from anywhere
    // in a probe's import graph — a dependency with an exports problem of its
    // own — and on the auth probe, which imports no subpath at all, it cannot
    // mean "your @cipherstash/stack is too old". Answering a broken install
    // with an unrelated upgrade and exiting 0 is a worse outcome than not
    // classifying it.
    const r = render(['doctor'], {
      env: {
        NODE_OPTIONS: unresolve({
          specifier: '@cipherstash/auth',
          // An auth package whose `exports` does not answer its own root —
          // same error code as the case above, from a package the arm has no
          // advice for.
          installed: {
            pkg: '@cipherstash/auth',
            exports: { './sub': './sub.js' },
          },
        }),
      },
      cols: 140,
    })
    const { exitCode } = await r.exit

    expect(r.output).not.toContain(messages.doctor.cannotProbe)
    expect(r.output).not.toContain(messages.doctor.allChecksPassed)
    expect(exitCode, r.output).toBe(1)
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
