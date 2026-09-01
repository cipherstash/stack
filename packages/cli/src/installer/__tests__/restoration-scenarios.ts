export interface SearchIndexRestorationScenario {
  identity: string
  tableIdentity: string
  definition: string
  valid: boolean
  ready: boolean
  clustered: boolean
  clusterSql: string | null
}

export type RestorationEvent =
  | 'begin'
  | 'lock'
  | 'configure'
  | 'capture'
  | 'replace'
  | 'reconstruct'
  | 'cluster'
  | 'analyze'
  | 'verify'
  | 'commit'
  | 'rollback'

export function searchIndexRestorationScenario(
  overrides: Partial<SearchIndexRestorationScenario> = {},
): SearchIndexRestorationScenario {
  return {
    identity: 'app.users_email_idx',
    tableIdentity: 'app.users',
    definition:
      'CREATE INDEX users_email_idx ON app.users USING btree (eql_v3.eq_term(email))',
    valid: true,
    ready: true,
    clustered: false,
    clusterSql: null,
    ...overrides,
  }
}

/** Recording PostgreSQL adapter for deterministic restoration protocol tests. */
export class RecordingRestorationDatabase {
  readonly events: RestorationEvent[] = []

  constructor(
    private readonly scenario?: SearchIndexRestorationScenario,
    private readonly options: {
      unsafeIdentity?: string
      failReconstructionWith?: Error
      failConfigurationWith?: Error
    } = {},
  ) {}

  query = async (
    sql: string,
  ): Promise<{ rows: unknown[]; rowCount: number }> => {
    const event = restorationEvent(sql, this.scenario)
    if (event !== null) this.events.push(event)

    if (event === 'lock') return { rows: [{ acquired: true }], rowCount: 1 }
    if (event === 'configure' && this.options.failConfigurationWith) {
      throw this.options.failConfigurationWith
    }
    if (event === 'capture') {
      if (this.options.unsafeIdentity) {
        return {
          rows: [
            {
              dependency_kind: 'unsafe',
              identity: this.options.unsafeIdentity,
            },
          ],
          rowCount: 1,
        }
      }
      return this.scenario
        ? { rows: [captureRow(this.scenario)], rowCount: 1 }
        : { rows: [], rowCount: 0 }
    }
    if (event === 'reconstruct' && this.options.failReconstructionWith) {
      throw this.options.failReconstructionWith
    }
    if (event === 'verify' && this.scenario) {
      return { rows: [verificationRow(this.scenario)], rowCount: 1 }
    }
    return { rows: [], rowCount: 0 }
  }
}

/** Live PostgreSQL adapter for catalog behavior that a recording cannot prove. */
export class LiveRestorationDatabase {
  constructor(readonly url: string) {}

  withEqlSearchPath(): LiveRestorationDatabase {
    const parsed = new URL(this.url)
    parsed.searchParams.set(
      'options',
      '-c search_path=public,eql_v3,eql_v3_internal',
    )
    return new LiveRestorationDatabase(parsed.toString())
  }

  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<T[]> {
    const { default: pg } = await import('pg')
    const client = new pg.Client({ connectionString: this.url })
    await client.connect()
    try {
      return (await client.query(sql, params)).rows as T[]
    } finally {
      await client.end().catch(() => undefined)
    }
  }

  dependencyInventory<T>(operators: string[], casts: string[]): Promise<T[]> {
    return this.query<T>(
      derivedSearchIndexRestorationTestSeam.lifecycleDependenciesSql,
      [operators, casts],
    )
  }
}

function captureRow(scenario: SearchIndexRestorationScenario) {
  return {
    dependency_kind: 'index',
    identity: scenario.identity,
    definition: scenario.definition,
    table_identity: scenario.tableIdentity,
    valid: scenario.valid,
    ready: scenario.ready,
    clustered: scenario.clustered,
    cluster_sql: scenario.clusterSql,
  }
}

function verificationRow(scenario: SearchIndexRestorationScenario) {
  return {
    identity: scenario.identity,
    definition: scenario.definition,
    valid: scenario.valid,
    ready: scenario.ready,
    clustered: scenario.clustered,
  }
}

function restorationEvent(
  sql: string,
  scenario?: SearchIndexRestorationScenario,
): RestorationEvent | null {
  if (sql === 'BEGIN') return 'begin'
  if (sql.includes('pg_try_advisory_xact_lock')) return 'lock'
  if (sql === 'SET LOCAL jit = off') return 'configure'
  if (sql.includes('stash_eql_lifecycle_dependencies')) return 'capture'
  if (sql.includes('CREATE SCHEMA eql_v3')) return 'replace'
  if (scenario && sql === scenario.definition) return 'reconstruct'
  if (scenario?.clusterSql && sql === scenario.clusterSql) return 'cluster'
  if (sql.startsWith('ANALYZE ')) return 'analyze'
  if (sql.includes('stash_eql_verify_rebuilt_indexes')) return 'verify'
  if (sql === 'COMMIT') return 'commit'
  if (sql === 'ROLLBACK') return 'rollback'
  return null
}

import { derivedSearchIndexRestorationTestSeam } from '../derived-search-index-restoration.js'
