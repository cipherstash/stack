import { protect } from '@cipherstash/protect'

/** Protect 10.2.1 needs explicit managed endpoints outside ap-southeast-2. */
export async function legacyProtect(
  schemas: Parameters<typeof protect>[0]['schemas'],
) {
  const crn = process.env.CS_WORKSPACE_CRN
  if (!crn) throw new Error('CS_WORKSPACE_CRN is required')
  const region = crn.split(':')[1]
  const saved = {
    CS_CTS_HOST: process.env.CS_CTS_HOST,
    CS_ZEROKMS_HOST: process.env.CS_ZEROKMS_HOST,
  }
  process.env.CS_CTS_HOST = `https://${region}.cts.cipherstashmanaged.net`
  process.env.CS_ZEROKMS_HOST = `https://${region}.viturhosted.net`
  try {
    return await protect({
      schemas,
      workspaceCrn: crn,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
    })
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

/** Check every SDK result; never continue with a failed encryption operation. */
export function ok<T>(
  result: { data: T; failure?: undefined } | { failure: unknown },
  label: string,
): T {
  if ('failure' in result && result.failure !== undefined) {
    throw new Error(`${label} failed`, { cause: result.failure })
  }
  if ('data' in result) return result.data
  throw new Error(`${label} returned no data`)
}
