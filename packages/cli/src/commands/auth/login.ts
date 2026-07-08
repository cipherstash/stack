import auth from '@cipherstash/auth'
import * as p from '@clack/prompts'
import { emitJsonError, emitJsonEvent } from './events.js'

const { beginDeviceCodeFlow, bindClientDevice } = auth

export interface LoginOptions {
  /**
   * Emit newline-delimited JSON events instead of pretty clack output, so an
   * agent can capture the device-code URL as data and trigger the flow for a
   * human to complete. Events (one JSON object per line, all on stdout):
   *   { status: 'authorization_required', userCode, verificationUri,
   *     verificationUriComplete, expiresIn }   — emitted immediately
   *   { status: 'authorized', expiresAt, expiresAtIso }  — on success
   *   { status: 'error', code?, message }                — on failure
   */
  json?: boolean
  /**
   * Whether to auto-open the verification URL in the user's browser. Defaults
   * to true in interactive mode, but false when `json` is set: a `--json` run
   * is the agent-trigger path, where the human — not the agent host — opens the
   * URL, so auto-opening a browser on the agent's machine is wrong. `--no-open`
   * forces it false in interactive mode too.
   */
  open?: boolean
}

/** Best-effort `.code` from an `@cipherstash/auth` AuthError, else undefined. */
function authErrorCode(err: unknown): string | undefined {
  return err && typeof err === 'object' && 'code' in err
    ? String((err as { code: unknown }).code)
    : undefined
}

export async function login(
  region: string,
  _referrer: string | undefined,
  opts: LoginOptions = {},
) {
  const json = opts.json ?? false
  // Default: open in interactive mode, never in json/agent mode. `--no-open`
  // (open === false) overrides in either mode.
  const openBrowser = opts.open ?? !json

  // Spinner and pretty logs would corrupt the JSON stream — suppress in json mode.
  const s = json ? null : p.spinner()

  // Must be 'cli' — it's the only OAuth client_id registered with CTS.
  // Passing anything else (e.g. `cli-supabase`) causes INVALID_CLIENT.
  let pending: Awaited<ReturnType<typeof beginDeviceCodeFlow>>
  try {
    pending = await beginDeviceCodeFlow(region, 'cli')
  } catch (err) {
    if (json) {
      emitJsonError(
        authErrorCode(err) ?? 'begin_failed',
        err instanceof Error ? err.message : 'Unknown error',
      )
      process.exit(1)
    }
    throw err
  }

  if (json) {
    // The "trigger" event — an agent surfaces verificationUriComplete to the
    // human, who completes authorization in their browser.
    emitJsonEvent({
      status: 'authorization_required',
      userCode: pending.userCode,
      verificationUri: pending.verificationUri,
      verificationUriComplete: pending.verificationUriComplete,
      expiresIn: pending.expiresIn,
    })
  } else {
    p.log.info(`Your code is: ${pending.userCode}`)
    p.log.info(`Visit: ${pending.verificationUriComplete}`)
    p.log.info(`Code expires in: ${pending.expiresIn}s`)
  }

  if (openBrowser) {
    const opened = pending.openInBrowser()
    if (!opened && !json) {
      p.log.warn(
        'Could not open browser — please visit the URL above manually.',
      )
    }
  }

  s?.start('Waiting for authorization...')
  let authResult: Awaited<ReturnType<typeof pending.pollForToken>>
  try {
    authResult = await pending.pollForToken()
  } catch (err) {
    s?.stop('Authorization failed.')
    if (json) {
      emitJsonError(
        authErrorCode(err) ?? 'poll_failed',
        err instanceof Error ? err.message : 'Unknown error',
      )
      process.exit(1)
    }
    throw err
  }
  s?.stop('Authenticated!')

  const expiresAtIso = new Date(authResult.expiresAt * 1000).toISOString()
  if (json) {
    emitJsonEvent({
      status: 'authorized',
      expiresAt: authResult.expiresAt,
      expiresAtIso,
    })
  } else {
    p.log.info(`Token expires at: ${expiresAtIso}`)
  }
}

export interface BindDeviceOptions {
  /** Emit a JSON event instead of pretty clack output. */
  json?: boolean
}

export async function bindDevice(opts: BindDeviceOptions = {}) {
  const json = opts.json ?? false
  const s = json ? null : p.spinner()
  s?.start('Binding device to the default Keyset...')

  try {
    await bindClientDevice()
    if (json) {
      emitJsonEvent({ status: 'device_bound' })
    } else {
      s?.stop('Your device has been bound to the default Keyset!')
    }
  } catch (error) {
    if (json) {
      emitJsonError(
        authErrorCode(error) ?? 'bind_failed',
        error instanceof Error ? error.message : 'Unknown error',
      )
    } else {
      s?.stop('Failed to bind your device to the default Keyset!')
      p.log.error(error instanceof Error ? error.message : 'Unknown error')
    }
    process.exit(1)
  }
}
