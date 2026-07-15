import * as p from '@clack/prompts'
import { CliExit } from '../../cli/exit.js'
import { messages } from '../../messages.js'
import {
  setTelemetryDisabled,
  type TelemetryDisabledReason,
  telemetryStatus,
} from '../../telemetry/index.js'

/** Human-readable explanation for why telemetry is currently off. */
function reasonText(reason: TelemetryDisabledReason): string {
  switch (reason) {
    case 'do-not-track':
      return 'disabled by the DO_NOT_TRACK environment variable'
    case 'stash-disabled':
      return 'disabled by the STASH_TELEMETRY_DISABLED environment variable'
    case 'ci':
      return 'disabled automatically in CI'
    case 'config':
      return 'disabled (run `stash telemetry enable` to turn it back on)'
    case 'unconfigured':
      return 'not active in this build'
  }
}

function printStatus(): void {
  const status = telemetryStatus()
  if (status.enabled) {
    p.log.info('Telemetry is enabled. Anonymous usage analytics are collected.')
    return
  }
  p.log.info(`Telemetry is ${reasonText(status.reason)}.`)
  // An env override wins over the persisted flag, so flag `enable` won't help.
  if (status.reason === 'do-not-track' || status.reason === 'stash-disabled') {
    p.log.info(
      'An environment variable is overriding your saved preference; unset it to re-enable.',
    )
  }
}

/**
 * `stash telemetry [status|enable|disable]` — manage anonymous CLI analytics.
 * `enable`/`disable` write the persisted opt-out flag; `status` (the default)
 * reports the current state and which gate governs it.
 */
export async function telemetryCommand(sub: string | undefined): Promise<void> {
  switch (sub) {
    case undefined:
    case 'status':
      printStatus()
      break
    case 'enable':
      setTelemetryDisabled(false)
      p.log.success(messages.telemetry.enabled)
      printStatus()
      break
    case 'disable':
      setTelemetryDisabled(true)
      p.log.success(messages.telemetry.disabled)
      break
    default:
      p.log.error(`${messages.telemetry.unknownSubcommand}: ${sub}`)
      throw new CliExit(1)
  }
}
