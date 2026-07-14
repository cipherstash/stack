import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { readState, writeState } from '../state.js'

let home: string

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-telemetry-'))
  process.env.HOME = home
})

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true })
})

const file = () => path.join(home, '.cipherstash', 'telemetry.json')

describe('telemetry state', () => {
  it('returns a fresh default (with an id) when no file exists', () => {
    const state = readState()
    expect(state.telemetryDisabled).toBe(false)
    expect(state.noticeShownAt).toBeUndefined()
    expect(state.anonymousId).toMatch(/[0-9a-f-]{36}/)
  })

  it('persists 0600 and round-trips', () => {
    const written = writeState({
      anonymousId: 'anon-x',
      telemetryDisabled: true,
      noticeShownAt: '2026-07-14T00:00:00.000Z',
    })
    expect(readState()).toEqual(written)
    // Private to the user — never group/world readable.
    expect(fs.statSync(file()).mode & 0o077).toBe(0)
  })

  it('recovers from a corrupt file with a fresh id, never throwing', () => {
    fs.mkdirSync(path.dirname(file()), { recursive: true })
    fs.writeFileSync(file(), '{ this is not json')
    const state = readState()
    expect(state.anonymousId).toMatch(/[0-9a-f-]{36}/)
    expect(state.telemetryDisabled).toBe(false)
  })

  it('coerces a partial/garbage object to valid defaults', () => {
    fs.mkdirSync(path.dirname(file()), { recursive: true })
    fs.writeFileSync(
      file(),
      JSON.stringify({ telemetryDisabled: 'yes', noticeShownAt: 42 }),
    )
    const state = readState()
    // A non-boolean flag is not treated as opted out; a non-string ts is dropped.
    expect(state.telemetryDisabled).toBe(false)
    expect(state.noticeShownAt).toBeUndefined()
    expect(state.anonymousId).toMatch(/[0-9a-f-]{36}/)
  })
})
