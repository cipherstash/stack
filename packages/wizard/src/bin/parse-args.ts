/**
 * Pure CLI argument parser for the wizard binary. Lives in its own module
 * so tests can import it without triggering the binary's top-level
 * `main()` side effect.
 */

import type { WizardMode } from '../lib/types.js'

export interface ParsedArgs {
  help: boolean
  version: boolean
  debug: boolean
  mode: WizardMode
  modeError?: string
}

export function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2)
  const flags = new Set(args)

  let mode: WizardMode = 'implement'
  let modeError: string | undefined

  // Last mode-setting flag wins so wrappers can append `--plan` /
  // `--implement` without first scrubbing an earlier value.
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '--plan') {
      mode = 'plan'
      continue
    }
    if (arg === '--implement') {
      mode = 'implement'
      continue
    }
    if (arg === '--mode') {
      if (i + 1 >= args.length) {
        modeError = "--mode requires a value. Expected 'plan' or 'implement'."
        break
      }
      const next = args[i + 1]
      if (next === 'plan' || next === 'implement') {
        mode = next
        i++
      } else {
        modeError = `Unknown --mode value: ${next}. Expected 'plan' or 'implement'.`
        break
      }
      continue
    }
    if (arg.startsWith('--mode=')) {
      const value = arg.slice('--mode='.length)
      if (value === 'plan' || value === 'implement') {
        mode = value
      } else {
        modeError = `Unknown --mode value: ${value}. Expected 'plan' or 'implement'.`
        break
      }
    }
  }

  return {
    help: flags.has('--help') || flags.has('-h'),
    version: flags.has('--version') || flags.has('-v'),
    debug: flags.has('--debug'),
    mode,
    modeError,
  }
}
