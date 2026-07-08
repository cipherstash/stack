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
  // As of `@cipherstash/auth` `0.41`, the device-code flow returns
  // `Result<T, AuthFailure>` instead of throwing — unwrap each step, and
  // surface the failure `type` (machine-readable) + message on the JSON stream.
  const pending = await beginDeviceCodeFlow(region, 'cli')
  if (pending.failure) {
    if (json) {
      emitJsonError(
        pending.failure.type ?? 'begin_failed',
        pending.failure.error.message,
      )
    } else {
      p.log.error(pending.failure.error.message)
    }
    process.exit(1)
  }
  const flow = pending.data

  if (json) {
    // The "trigger" event — an agent surfaces verificationUriComplete to the
    // human, who completes authorization in their browser.
    emitJsonEvent({
      status: 'authorization_required',
      userCode: flow.userCode,
      verificationUri: flow.verificationUri,
      verificationUriComplete: flow.verificationUriComplete,
      expiresIn: flow.expiresIn,
    })
  } else {
    p.log.info(`Your code is: ${flow.userCode}`)
    p.log.info(`Visit: ${flow.verificationUriComplete}`)
    p.log.info(`Code expires in: ${flow.expiresIn}s`)
  }

  if (openBrowser) {
    const opened = flow.openInBrowser()
    if ((opened.failure || !opened.data) && !json) {
      p.log.warn(
        'Could not open browser — please visit the URL above manually.',
      )
    }
  }

  s?.start('Waiting for authorization...')
  const authResult = await flow.pollForToken()
  if (authResult.failure) {
    s?.stop('Authorization failed.')
    if (json) {
      emitJsonError(
        authResult.failure.type ?? 'poll_failed',
        authResult.failure.error.message,
      )
    } else {
      p.log.error(authResult.failure.error.message)
    }
    process.exit(1)
  }
  s?.stop('Authenticated!')

  const expiresAtIso = new Date(authResult.data.expiresAt * 1000).toISOString()
  if (json) {
    emitJsonEvent({
      status: 'authorized',
      expiresAt: authResult.data.expiresAt,
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

  // `bindClientDevice()` returns `Result<void, AuthFailure>` as of
  // `@cipherstash/auth` `0.41` — a failure no longer throws.
  const result = await bindClientDevice()
  if (result.failure) {
    if (json) {
      emitJsonError(
        result.failure.type ?? 'bind_failed',
        result.failure.error.message,
      )
    } else {
      s?.stop('Failed to bind your device to the default Keyset!')
      p.log.error(result.failure.error.message)
    }
    process.exit(1)
  }

  if (json) {
    emitJsonEvent({ status: 'device_bound' })
  } else {
    s?.stop('Your device has been bound to the default Keyset!')
  }
}
