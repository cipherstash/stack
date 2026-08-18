/**
 * The one place the CLI turns a database URL into a `pg.Client`. The TLS
 * policy — `sslmode`/`sslrootcert` handling, the bundled Supabase root CA,
 * and cert-error shaping — lives in `./config.ts`; this module just binds it
 * to the driver.
 */

import pg from 'pg'
import {
  buildPgClientConfig,
  explainTlsError,
  TlsVerificationError,
} from './config.js'

export {
  buildPgClientConfig,
  explainTlsError,
  resetNoVerifyWarningForTests,
  TlsVerificationError,
} from './config.js'

/**
 * Build a client whose `connect()` re-throws certificate-verification
 * failures as {@link TlsVerificationError} carrying the shaped remedy —
 * centrally, so every command that awaits `connect()` surfaces the
 * host-specific fix without each call site knowing about TLS. Non-TLS
 * failures pass through untouched.
 */
export function createPgClient(
  databaseUrl: string,
  extra: Omit<pg.ClientConfig, 'connectionString' | 'ssl'> = {},
): pg.Client {
  const client = new pg.Client(buildPgClientConfig(databaseUrl, extra))
  const originalConnect = client.connect.bind(client)
  const wrappedConnect = async (): Promise<void> => {
    try {
      await originalConnect()
    } catch (error) {
      if (error instanceof TlsVerificationError) throw error
      const explanation = explainTlsError(error, databaseUrl)
      if (explanation) {
        throw new TlsVerificationError(explanation, { cause: error })
      }
      throw error
    }
  }
  // Every CLI call site uses the promise form; the callback overload is not
  // used and the assertion narrows to the declared union.
  client.connect = wrappedConnect as typeof client.connect
  return client
}
