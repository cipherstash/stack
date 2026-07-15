import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/**
 * Machine-level telemetry state, persisted alongside the auth profile in
 * `~/.cipherstash/` but in its own file. We only ever read/write `telemetry.json`
 * here — never the auth secrets (`auth.json`, `secretkey.json`, `workspaces/`).
 *
 * The file holds three things: a random anonymous id (for de-duplicating events
 * in aggregate, never derivable to a person), the persisted opt-out flag written
 * by `stash telemetry disable`, and the timestamp of the first-run notice so the
 * banner shows exactly once per install.
 */
export interface TelemetryState {
  /** Random UUID; the PostHog `distinctId`. Not tied to any identity. */
  anonymousId: string
  /** Set by `stash telemetry disable`. The lowest-precedence opt-out gate. */
  telemetryDisabled: boolean
  /** ISO timestamp the first-run notice was shown; unset means "never shown". */
  noticeShownAt?: string
}

/** Resolved at call time so it always tracks the current home directory. */
function stateDir(): string {
  return path.join(os.homedir(), '.cipherstash')
}
function stateFile(): string {
  return path.join(stateDir(), 'telemetry.json')
}

/** Coerce arbitrary parsed JSON into a valid state, filling gaps with defaults. */
function normalize(value: unknown): TelemetryState {
  const o = (
    typeof value === 'object' && value !== null ? value : {}
  ) as Record<string, unknown>
  return {
    anonymousId:
      typeof o.anonymousId === 'string' && o.anonymousId.length > 0
        ? o.anonymousId
        : randomUUID(),
    telemetryDisabled: o.telemetryDisabled === true,
    noticeShownAt:
      typeof o.noticeShownAt === 'string' ? o.noticeShownAt : undefined,
  }
}

/**
 * Read the state file. Never throws: a missing or corrupt file yields a fresh
 * default (with a new anonymous id), so a bad file can never break a command.
 * The fresh id is only ephemeral until something calls {@link writeState}.
 */
export function readState(): TelemetryState {
  try {
    return normalize(JSON.parse(fs.readFileSync(stateFile(), 'utf-8')))
  } catch {
    return { anonymousId: randomUUID(), telemetryDisabled: false }
  }
}

/**
 * Persist state (0600, private). Returns the normalized value actually written.
 * Unlike {@link readState} this may throw — callers that must not fail a command
 * (the emitter) wrap it; the `stash telemetry` command lets a write error surface.
 */
export function writeState(state: TelemetryState): TelemetryState {
  const normalized = normalize(state)
  fs.mkdirSync(stateDir(), { recursive: true })
  fs.writeFileSync(stateFile(), `${JSON.stringify(normalized, null, 2)}\n`, {
    mode: 0o600,
  })
  return normalized
}
