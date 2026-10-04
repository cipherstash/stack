import * as p from '@clack/prompts'
import { messages } from '../../messages.js'
import { isPackageMissing, isSubpathUnavailable } from '../../module-error.js'
import {
  currentTarget,
  isNativeBinaryMissing,
  reportNativeBinaryMissing,
} from '../../native.js'

// Native-bearing packages the CLI loads at runtime, and — per package — the
// operation that forces its platform binary to resolve.
//
// Importing a package is not a probe on its own. It was, for protect-ffi, until
// the load became lazy: `@neon-rs/load`'s proxy now resolves the binary on
// first property access inside a wrapper body, so the package imports cleanly
// with nothing installed and fails at the first encrypt instead. Each probe
// therefore names what to CALL, not just what to import.
interface Probe {
  label: string
  /**
   * The package a "not installed" message names, which is not always what the
   * probe imports: Node reports the base package for a missing subpath of an
   * absent package, so the encryption probe imports `…/diagnostics` and
   * classifies against `@cipherstash/stack`.
   */
  pkg: string
  /**
   * The subpath of `pkg` that `force()` imports, when it imports one. Only a
   * probe that asks for a subpath can fail for want of it, so this is what
   * scopes the too-old-to-probe arm to the probe it has advice for.
   */
  subpath?: string
  /** May legitimately be absent until `stash init`, so absence is not failure. */
  optional?: boolean
  force(): Promise<void>
}

const PROBES: Probe[] = [
  {
    label: messages.doctor.encryptionProbeLabel,
    pkg: '@cipherstash/stack',
    subpath: './diagnostics',
    optional: true,
    async force() {
      // `@cipherstash/stack/diagnostics` exists for this call: it reaches
      // protect-ffi WITHOUT reaching `@cipherstash/auth`, which the root entry
      // does (it re-exports the auth strategies, and that package's binding is
      // eager). Probing the root entry measured auth's binary and reported it
      // under this label — two rows, one signal.
      const diagnostics = await import('@cipherstash/stack/diagnostics')
      diagnostics.assertNativeBindingAvailable()
    },
  },
  {
    label: messages.doctor.authProbeLabel,
    pkg: '@cipherstash/auth',
    async force() {
      // No counterpart call needed. This package's entry is `module.exports =
      // { ...native }`, and the spread resolves the binding at module
      // evaluation — so here the import IS the probe.
      await import('@cipherstash/auth')
    },
  },
]

type Outcome = 'ok' | 'warn' | 'fail'

function report(outcome: Outcome, label: string, detail?: string) {
  const text = detail ? `${label} — ${detail}` : label
  if (outcome === 'ok') p.log.success(text)
  else if (outcome === 'warn') p.log.warn(text)
  else p.log.error(text)
}

export async function doctorCommand(): Promise<void> {
  p.intro(messages.doctor.title)

  let failed = false
  // A check that could not be RUN, as distinct from one that ran and failed.
  // Tracked separately so the outro can say so — `failed` would exit 1 on an
  // install with nothing known to be wrong with it, and neither flag would
  // claim every check passed.
  let incomplete = false
  let nativeError: unknown

  const nodeMajor = Number(process.versions.node.split('.')[0])
  const nodeOk = Number.isFinite(nodeMajor) && nodeMajor >= 22
  report(
    nodeOk ? 'ok' : 'fail',
    `Node.js ${process.versions.node}`,
    nodeOk ? '' : 'requires >= 22',
  )
  if (!nodeOk) failed = true

  report('ok', `${messages.doctor.platformLabel} ${currentTarget()}`)

  for (const probe of PROBES) {
    try {
      await probe.force()
      report('ok', probe.label)
    } catch (err) {
      if (isNativeBinaryMissing(err)) {
        report('fail', probe.label, messages.doctor.nativeBinaryMissing)
        failed = true
        // First one wins. The guidance below is the same whichever package
        // reported it; keeping the first keeps the note aligned with the first
        // failing row rather than the last.
        nativeError ??= err
      } else if (isPackageMissing(err, probe.pkg)) {
        // A missing top-level package is a different problem from a missing
        // native binary; only the latter is what these guards exist for.
        report(
          probe.optional ? 'ok' : 'fail',
          probe.label,
          probe.optional
            ? messages.doctor.notInstalledOptional
            : messages.doctor.notInstalled,
        )
        // The row stays green — absence before `stash init` is expected, and
        // the detail already says so — but the check did not RUN, which is the
        // same thing the too-old arm below records. Without this the outro said
        // every check passed while one of the two never executed.
        if (probe.optional) incomplete = true
        else failed = true
      } else if (isSubpathUnavailable(err, probe)) {
        report('warn', probe.label, messages.doctor.cannotProbe)
        incomplete = true
      } else {
        throw err
      }
    }
  }

  if (nativeError) {
    reportNativeBinaryMissing(nativeError)
  }

  if (failed) {
    p.outro(messages.doctor.problemsFound)
    process.exit(1)
  }
  // Exit 0 either way — an unrunnable check is not a diagnosis — but only one
  // of these two is true.
  p.outro(
    incomplete
      ? messages.doctor.checksIncomplete
      : messages.doctor.allChecksPassed,
  )
}
