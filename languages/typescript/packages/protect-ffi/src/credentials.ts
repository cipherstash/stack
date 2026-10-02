export type CredentialOpts = {
  /** Full workspace CRN, e.g. `crn:ap-southeast-2.aws:<workspace-id>`. */
  workspaceCrn?: string
  accessKey?: string
  /** UUID. A malformed value is rejected at the options boundary. */
  clientId?: string
  /**
   * Hex-encoded client key.
   *
   * Hex only. The base64 form `~/.cipherstash/secretkey.json` stores on disk
   * used to be accepted here too, and is not any more — see the CHANGELOG.
   * This is also what `CS_CLIENT_KEY` is forwarded as.
   */
  clientKey?: string
}

/** Reads an environment variable. Replaceable in tests. */
export type EnvReader = (key: string) => string | undefined

const processEnv: EnvReader = (key) => process.env[key]

/** Fill in credential fields from env vars when not explicitly set. */
export function withEnvCredentials<T extends CredentialOpts>(
  opts: T,
  env?: EnvReader,
): T
export function withEnvCredentials(
  opts: CredentialOpts | undefined,
  env?: EnvReader,
): CredentialOpts
export function withEnvCredentials<T extends CredentialOpts>(
  opts: T | undefined,
  env: EnvReader = processEnv,
): T | CredentialOpts {
  // CS_CLIENT_ID and CS_CLIENT_KEY are a keypair — only use them when both are set
  const envClientId = env('CS_CLIENT_ID')
  const envClientKey = env('CS_CLIENT_KEY')
  const hasEnvClientKey =
    envClientId !== undefined && envClientKey !== undefined

  const creds: CredentialOpts = {
    clientId: opts?.clientId ?? (hasEnvClientKey ? envClientId : undefined),
    clientKey: opts?.clientKey ?? (hasEnvClientKey ? envClientKey : undefined),
    workspaceCrn: opts?.workspaceCrn ?? env('CS_WORKSPACE_CRN'),
    accessKey: opts?.accessKey ?? env('CS_ACCESS_KEY'),
  }
  return opts ? { ...opts, ...creds } : creds
}
