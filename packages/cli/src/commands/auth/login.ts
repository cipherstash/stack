import auth from '@cipherstash/auth'
import * as p from '@clack/prompts'
import { messages } from '../../messages.js'

const { beginDeviceCodeFlow, bindClientDevice } = auth

// TODO: pull from the CTS API
export const regions = [
  { value: 'us-east-1.aws', label: 'us-east-1 (Virginia, USA)' },
  { value: 'us-east-2.aws', label: 'us-east-2 (Ohio, USA)' },
  { value: 'us-west-1.aws', label: 'us-west-1 (California, USA)' },
  { value: 'us-west-2.aws', label: 'us-west-2 (Oregon, USA)' },
  { value: 'ap-southeast-2.aws', label: 'ap-southeast-2 (Sydney, Australia)' },
  { value: 'eu-central-1.aws', label: 'eu-central-1 (Frankfurt, Germany)' },
  { value: 'eu-west-1.aws', label: 'eu-west-1 (Dublin, Ireland)' },
]

export async function selectRegion(): Promise<string> {
  const region = await p.select({
    message: messages.auth.selectRegion,
    options: regions,
  })

  if (p.isCancel(region)) {
    p.cancel(messages.auth.cancelled)
    process.exit(0)
  }

  return region
}

export async function login(region: string, _referrer: string | undefined) {
  const s = p.spinner()

  // Must be 'cli' — it's the only OAuth client_id registered with CTS.
  // Passing anything else (e.g. `cli-supabase`) causes INVALID_CLIENT.
  // As of `@cipherstash/auth` `0.41`, the device-code flow returns
  // `Result<T, AuthFailure>` instead of throwing — unwrap each step.
  const pending = await beginDeviceCodeFlow(region, 'cli')
  if (pending.failure) {
    p.log.error(pending.failure.error.message)
    process.exit(1)
  }
  const flow = pending.data

  p.log.info(`Your code is: ${flow.userCode}`)
  p.log.info(`Visit: ${flow.verificationUriComplete}`)
  p.log.info(`Code expires in: ${flow.expiresIn}s`)

  const opened = flow.openInBrowser()
  if (opened.failure || !opened.data) {
    p.log.warn('Could not open browser — please visit the URL above manually.')
  }

  s.start('Waiting for authorization...')
  const auth = await flow.pollForToken()
  if (auth.failure) {
    s.stop('Authentication failed!')
    p.log.error(auth.failure.error.message)
    process.exit(1)
  }
  s.stop('Authenticated!')

  p.log.info(
    `Token expires at: ${new Date(auth.data.expiresAt * 1000).toISOString()}`,
  )
}

export async function bindDevice() {
  const s = p.spinner()
  s.start('Binding device to the default Keyset...')

  // `bindClientDevice()` returns `Result<void, AuthFailure>` as of
  // `@cipherstash/auth` `0.41` — a failure no longer throws.
  const result = await bindClientDevice()
  if (result.failure) {
    s.stop('Failed to bind your device to the default Keyset!')
    p.log.error(result.failure.error.message)
    process.exit(1)
  }
  s.stop('Your device has been bound to the default Keyset!')
}
