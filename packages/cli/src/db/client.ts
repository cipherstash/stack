/**
 * The one place the CLI turns a database URL into a `pg.Client`. The TLS
 * policy — `sslmode`/`sslrootcert` handling, the bundled Supabase root CA,
 * and cert-error shaping — lives in `./config.ts`; this module just binds it
 * to the driver.
 */

import pg from 'pg'
import { buildPgClientConfig } from './config.js'

export {
  buildPgClientConfig,
  explainTlsError,
  resetNoVerifyWarningForTests,
} from './config.js'

export function createPgClient(
  databaseUrl: string,
  extra: Omit<pg.ClientConfig, 'connectionString' | 'ssl'> = {},
): pg.Client {
  return new pg.Client(buildPgClientConfig(databaseUrl, extra))
}
