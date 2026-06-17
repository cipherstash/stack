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
  const pending = await beginDeviceCodeFlow(region, 'cli')

  p.log.info(`Your code is: ${pending.userCode}`)
  p.log.info(`Visit: ${pending.verificationUriComplete}`)
  p.log.info(`Code expires in: ${pending.expiresIn}s`)

  const opened = pending.openInBrowser()
  if (!opened) {
    p.log.warn('Could not open browser — please visit the URL above manually.')
  }

  s.start('Waiting for authorization...')
  const auth = await pending.pollForToken()
  s.stop('Authenticated!')

  p.log.info(
    `Token expires at: ${new Date(auth.expiresAt * 1000).toISOString()}`,
  )
}

export async function bindDevice() {
  const s = p.spinner()
  s.start('Binding device to the default Keyset...')

  try {
    await bindClientDevice()
    s.stop('Your device has been bound to the default Keyset!')
  } catch (error) {
    s.stop('Failed to bind your device to the default Keyset!')
    p.log.error(error instanceof Error ? error.message : 'Unknown error')
    process.exit(1)
  }
}
