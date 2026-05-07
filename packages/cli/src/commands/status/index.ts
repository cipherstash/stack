import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { latestByColumn, readManifest } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { readContextFile } from '../init/lib/read-context.js'
import { PLAN_REL_PATH } from '../init/lib/setup-prompt.js'
import {
  type ContextFile,
  SETUP_PROMPT_REL_PATH,
} from '../init/lib/write-context.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'
import {
  type ColumnObservation,
  type QuestLog,
  buildQuestLog,
} from './quest.js'
import {
  renderQuestLogJSON,
  renderQuestLogPlain,
  renderQuestLogTTY,
} from './render.js'

export type StageStatus = 'done' | 'pending'

export interface ProjectStatus {
  initialized: boolean
  context?: ContextFile
  planExists: boolean
  /** Setup-prompt is written by every `stash impl` run, regardless of mode.
   *  Its presence means the user has handed off to an agent at least once. */
  agentEngaged: boolean
}

export function readProjectStatus(cwd: string): ProjectStatus {
  const context = readContextFile(cwd)
  return {
    initialized: context !== undefined,
    context,
    planExists: existsSync(resolve(cwd, PLAN_REL_PATH)),
    agentEngaged: existsSync(resolve(cwd, SETUP_PROMPT_REL_PATH)),
  }
}

/**
 * Read the manifest + cs_migrations + EQL config + physical-column state
 * and assemble per-column observations. DB reachability is best-effort —
 * any error is swallowed and the result is `{ observedFromDb: false,
 * observations }` with `phase`/`eql` undefined per column.
 */
export async function gatherObservations(
  cwd: string,
): Promise<{ observedFromDb: boolean; observations: ColumnObservation[] }> {
  const manifest = await readManifest(cwd).catch(() => null)
  if (!manifest) {
    return { observedFromDb: false, observations: [] }
  }

  const targetColumns: { table: string; column: string }[] = []
  for (const [table, cols] of Object.entries(manifest.tables)) {
    for (const col of cols) {
      targetColumns.push({ table, column: col.column })
    }
  }

  if (targetColumns.length === 0) {
    return { observedFromDb: false, observations: [] }
  }

  let databaseUrl: string | undefined
  try {
    const { loadStashConfig } = await import('../../config/index.js')
    const config = await loadStashConfig()
    databaseUrl = config.databaseUrl
  } catch {
    // Couldn't load config — return manifest-only observations.
    return {
      observedFromDb: false,
      observations: targetColumns.map((c) => ({ ...c })),
    }
  }

  const client = new pg.Client({ connectionString: databaseUrl })
  try {
    await client.connect()
    const [phases, eqlConfig, physicalCols] = await Promise.all([
      latestByColumn(client).catch(() => new Map()),
      fetchEqlConfig(client),
      fetchPhysicalColumns(client),
    ])

    const observations: ColumnObservation[] = targetColumns.map((c) => {
      const key: `${string}.${string}` = `${c.table}.${c.column}`
      const phaseRow = phases.get(key)
      return {
        table: c.table,
        column: c.column,
        phase: phaseRow ? phaseRow.phase : null,
        eql: eqlConfig.get(key) ?? null,
        physicalEncryptedTwinExists: (
          physicalCols.get(c.table) ?? new Set()
        ).has(`${c.column}_encrypted`),
      }
    })

    return { observedFromDb: true, observations }
  } catch {
    return {
      observedFromDb: false,
      observations: targetColumns.map((c) => ({ ...c })),
    }
  } finally {
    await client.end().catch(() => undefined)
  }
}

async function fetchEqlConfig(
  client: pg.Client,
): Promise<Map<string, ColumnObservation['eql']>> {
  const out = new Map<string, ColumnObservation['eql']>()
  try {
    const result = await client.query<{ state: string; data: unknown }>(
      `SELECT state, data FROM public.eql_v2_configuration
       WHERE state IN ('active', 'pending', 'encrypting')
       ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'encrypting' THEN 1 ELSE 2 END`,
    )
    for (const row of result.rows) {
      const data = row.data as {
        tables?: Record<string, Record<string, unknown>>
      } | null
      if (!data?.tables) continue
      for (const [tableName, columns] of Object.entries(data.tables)) {
        for (const columnName of Object.keys(columns)) {
          const key = `${tableName}.${columnName}`
          if (out.has(key)) continue
          out.set(key, {
            state: row.state as 'active' | 'pending' | 'encrypting',
          })
        }
      }
    }
  } catch (err) {
    if (err instanceof Error && /eql_v2_configuration/i.test(err.message)) {
      return out
    }
    throw err
  }
  return out
}

async function fetchPhysicalColumns(
  client: pg.Client,
): Promise<Map<string, Set<string>>> {
  const out = new Map<string, Set<string>>()
  try {
    const result = await client.query<{
      table_name: string
      column_name: string
    }>(
      `SELECT table_name, column_name FROM information_schema.columns
       WHERE table_schema = current_schema()`,
    )
    for (const row of result.rows) {
      const set = out.get(row.table_name) ?? new Set<string>()
      set.add(row.column_name)
      out.set(row.table_name, set)
    }
  } catch {
    // information_schema is always present; if this fails, swallow.
  }
  return out
}

interface StatusFlags {
  /** Force the fancy quest-log output even in non-TTY contexts. */
  quest?: boolean
  /** Force a structured JSON output (machine-readable). */
  json?: boolean
  /** Force the plain-text fallback even in TTY contexts. */
  plain?: boolean
}

/**
 * `stash status` — the encryption rollout quest log.
 *
 * Reads `.cipherstash/context.json` to know whether init has run, then
 * (best-effort) consults `cs_migrations`, `eql_v2_configuration`, and
 * `information_schema` to derive per-column quest objectives. Renders
 * a quest-log shape with active/completed sections, progress bars, and
 * per-quest "next move" hints.
 *
 * Output mode:
 *   `--quest` forces the fancy TTY shape (works anywhere).
 *   `--plain` forces the emoji-free plain shape (works anywhere).
 *   `--json`  forces a structured JSON output (machine-readable).
 *   default — fancy in TTY, plain otherwise.
 */
export async function statusCommand(flags: StatusFlags = {}) {
  const cwd = process.cwd()
  const pm = detectPackageManager()
  const cli = runnerCommand(pm, 'stash')
  const project = readProjectStatus(cwd)

  if (flags.json) {
    const log = await buildLog(cwd, project)
    process.stdout.write(renderQuestLogJSON(log))
    return
  }

  // The intro/outro frames are TTY-only; in plain mode we want the raw
  // body without `clack` decorations so the output is grep-friendly.
  const log = await buildLog(cwd, project)

  const useTTY = flags.quest ?? (process.stdout.isTTY && !flags.plain)

  if (useTTY) {
    p.intro('CipherStash')
    p.note(renderQuestLogTTY(log), 'Quest log')
    p.outro(nextMoveHint(log, cli))
  } else {
    process.stdout.write(`${renderQuestLogPlain(log)}\n`)
    process.stdout.write(`Next: ${nextMoveHint(log, cli)}\n`)
  }
}

async function buildLog(
  cwd: string,
  project: ProjectStatus,
): Promise<QuestLog> {
  const { observedFromDb, observations } = project.initialized
    ? await gatherObservations(cwd)
    : { observedFromDb: false, observations: [] }
  return buildQuestLog({
    initialized: project.initialized,
    observedFromDb,
    observations,
  })
}

/**
 * One-line prompt for what to do next, used as the outro of both rendering
 * paths. Encodes the same routing the legacy `nextAction` helper used to:
 * "haven't init'd → init", "no quests → plan", "active quest → impl or
 * follow the per-quest hint", "everything done → relax".
 */
export function nextMoveHint(log: QuestLog, cli: string): string {
  if (!log.initialized) return `Run \`${cli} init\` to begin.`
  if (log.active.length === 0 && log.completed.length === 0) {
    return `Run \`${cli} plan\` to draft your encryption rollout.`
  }
  if (log.active.length === 0) {
    return 'All rollouts complete. Nothing to do.'
  }
  // First active quest's nextMove already names a concrete CLI invocation
  // when relevant; if not, fall back to a generic plan/impl pointer.
  const first = log.active[0]
  if (first.nextMove) return first.nextMove
  return `Run \`${cli} plan\` to draft the next step.`
}
