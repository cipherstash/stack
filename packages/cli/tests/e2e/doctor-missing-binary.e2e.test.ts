import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

// The case `stash doctor` exists for, and the one nothing covered: a platform
// binary that npm skipped (https://github.com/npm/cli/issues/4828).
//
// `doctor.e2e.test.ts` runs the healthy install. That cannot catch a probe that
// has stopped probing — and both of them had. Since the protect-ffi load became
// lazy, importing the package resolves no binary at all, so the encryption row
// went green with nothing installed; and `@cipherstash/auth`'s napi loader
// throws a code-less Error the CLI's classifier did not recognise, so a missing
// auth binary surfaced as a bare `Fatal error` with none of the recovery
// guidance. Both are only visible from outside the process, with a binary
// actually absent.
//
// Absent by patching the resolver in the spawned CLI, not by moving files: the
// suite must not mutate the checkout it runs in, and this works whether or not
// the developer has run `build:native`. Same technique as
// `packages/protect-ffi/src/lintWiring.test.ts`, which re-runs its own suite
// this way.

interface Target {
  /** Package whose platform binary disappears. */
  pkg: '@cipherstash/protect-ffi' | '@cipherstash/auth'
  /** The doctor row that must go red. */
  label: string
  /** Extra specifiers this package's loader reaches for. */
  extra: string
}

const TARGETS: Target[] = [
  {
    pkg: '@cipherstash/protect-ffi',
    label: messages.doctor.encryptionProbeLabel,
    // `src/load.cts`'s debug arm — a local cargo build sitting beside `lib/`.
    // A contributor who has run `pnpm run debug` has one, and without this the
    // fixture would load the binding it means to be missing.
    extra: String.raw`|(?:^|[\\/])index\.node$`,
  },
  {
    pkg: '@cipherstash/auth',
    label: messages.doctor.authProbeLabel,
    // napi's local-build arm, tried before the platform package.
    extra: String.raw`|(?:^|[\\/])stack-auth-node\.node$`,
  },
]

/**
 * Writes a CJS preload that makes `pkg`'s platform binary unresolvable, and
 * returns the `NODE_OPTIONS` value that loads it.
 *
 * `Module._load`, not `Module._resolveFilename`: `_load` keys a relative-resolve
 * fast path on (parent directory, request) and returns cached modules without
 * consulting the resolver, so a redirect installed there can simply never be
 * asked. `fs` is patched alongside it because a loader that stats an artifact
 * before requiring it would otherwise see a file that `require` then refuses.
 */
function hideBinaryOf(target: Target): string {
  const dir = mkdtempSync(join(tmpdir(), 'stash-doctor-missing-'))
  const preload = join(dir, 'hide-binding.cjs')
  const scope = target.pkg.replace('@cipherstash/', '')
  writeFileSync(
    preload,
    `
const fs = require('node:fs')
const Module = require('node:module')

const BINDING = /@cipherstash[\\\\/]${scope}-(?:darwin|linux|win32)-${target.extra}/

const load = Module._load
Module._load = function (request, parent, isMain) {
  if (BINDING.test(request)) {
    const error = new Error("Cannot find module '" + request + "'")
    error.code = 'MODULE_NOT_FOUND'
    throw error
  }
  return load.call(this, request, parent, isMain)
}

const existsSync = fs.existsSync
fs.existsSync = (p) => (BINDING.test(String(p)) ? false : existsSync(p))

const statSync = fs.statSync
fs.statSync = (p, ...rest) => {
  if (!BINDING.test(String(p))) return statSync(p, ...rest)
  const error = new Error('ENOENT: no such file or directory, stat ' + p)
  error.code = 'ENOENT'
  throw error
}

Module.syncBuiltinESMExports()
`,
  )
  // Quoted: Node splits NODE_OPTIONS on whitespace unless a value is wrapped in
  // double quotes, and `preload` sits under a tmpdir this file did not choose.
  return [process.env.NODE_OPTIONS, `--require "${preload}"`]
    .filter(Boolean)
    .join(' ')
}

const currentTarget = `${process.platform}-${process.arch}`

describe('stash doctor — a platform binary is missing', () => {
  it.each(TARGETS.map((t) => [t.pkg, t] as const))(
    'fails the %s row, names the package and exits non-zero',
    async (_pkg, target) => {
      // Wider than the 100-col default so the note's `Missing package:` line is
      // asserted as written rather than as clack happened to wrap it.
      const r = render(['doctor'], {
        env: { NODE_OPTIONS: hideBinaryOf(target) },
        cols: 140,
      })
      const { exitCode } = await r.exit

      expect(
        exitCode,
        `stash doctor passed with no ${target.pkg} binary installed:\n${r.output}`,
      ).toBe(1)
      expect(r.output).toContain(
        `${target.label} — ${messages.doctor.nativeBinaryMissing}`,
      )
      expect(r.output).toContain(messages.doctor.problemsFound)

      // The guidance, not just a red row: the platform package by name is the
      // one piece of it a user cannot work out for themselves.
      expect(r.output).toContain(`${target.pkg}-${currentTarget}`)
      expect(r.output).not.toContain('Fatal error')
    },
  )

  it('fails only the row whose binary is missing', async () => {
    // Non-vacuity for the pair above. Both probes went through
    // `@cipherstash/stack` before this change — the root entry reaches
    // `@cipherstash/auth`, whose binding is eager — so hiding auth's binary
    // reddened both rows and hiding protect-ffi's reddened neither. Either way
    // the two rows reported one signal, and the assertions above cannot see it.
    const protectFfi = TARGETS[0]
    if (!protectFfi) throw new Error('TARGETS is empty')

    const r = render(['doctor'], {
      env: { NODE_OPTIONS: hideBinaryOf(protectFfi) },
      cols: 140,
    })
    await r.exit

    // Counted by splitting, not by `new RegExp(message)`: the needle is copy
    // from `messages.ts`, and copy is free to grow a `.`, `(` or `?` — which a
    // regex would silently reinterpret rather than fail on.
    const failures =
      r.output.split(messages.doctor.nativeBinaryMissing).length - 1
    expect(failures, `expected exactly one failing row:\n${r.output}`).toBe(1)
    expect(r.output).toContain(protectFfi.label)
    expect(r.output).not.toContain('@cipherstash/auth-')
  })
})
