import * as p from '@clack/prompts'
import { messages } from '../../messages.js'
import {
  currentTarget,
  isNativeBinaryMissing,
  reportNativeBinaryMissing,
} from '../../native.js'

// Native-bearing packages the CLI loads at runtime. Importing each forces its
// @neon-rs/load proxy to resolve the platform binary — the same load that fails
// when npm skips the optional dependency. @cipherstash/stack is the peer that
// pulls protect-ffi; it may legitimately be absent until `stash init`.
const PROBES: { label: string; pkg: string; optional?: boolean }[] = [
  {
    label: 'Encryption engine (@cipherstash/stack → protect-ffi)',
    pkg: '@cipherstash/stack',
    optional: true,
  },
  { label: 'Auth (@cipherstash/auth)', pkg: '@cipherstash/auth' },
]

function report(ok: boolean, label: string, detail?: string) {
  const text = detail ? `${label} — ${detail}` : label
  if (ok) p.log.success(text)
  else p.log.error(text)
}

function isPackageMissing(err: unknown, pkg: string): boolean {
  if (!(err instanceof Error)) return false
  const code = (err as { code?: string }).code
  if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') {
    return false
  }
  return err.message.includes(pkg)
}

export async function doctorCommand(): Promise<void> {
  p.intro(messages.doctor.title)

  let failed = false
  let nativeError: unknown

  const nodeMajor = Number(process.versions.node.split('.')[0])
  const nodeOk = Number.isFinite(nodeMajor) && nodeMajor >= 22
  report(nodeOk, `Node.js ${process.versions.node}`, nodeOk ? '' : 'requires >= 22')
  if (!nodeOk) failed = true

  report(true, `${messages.doctor.platformLabel} ${currentTarget()}`)

  for (const probe of PROBES) {
    try {
      await import(probe.pkg)
      report(true, probe.label)
    } catch (err) {
      if (isNativeBinaryMissing(err)) {
        report(false, probe.label, 'native binary missing')
        failed = true
        nativeError = err
      } else if (isPackageMissing(err, probe.pkg)) {
        // A missing top-level package is a different problem from a missing
        // native binary; only the latter is what these guards exist for.
        report(
          Boolean(probe.optional),
          probe.label,
          probe.optional ? 'not installed (run `stash init`)' : 'not installed',
        )
        if (!probe.optional) failed = true
      } else {
        throw err
      }
    }
  }

  if (nativeError) {
    reportNativeBinaryMissing(nativeError)
  }

  if (failed) {
    p.outro('stash doctor found problems.')
    process.exit(1)
  }
  p.outro(messages.doctor.allChecksPassed)
}
