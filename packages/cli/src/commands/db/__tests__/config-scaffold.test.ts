import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CONFIG_FILENAME,
  DEFAULT_CLIENT_PATH,
  offerStashConfig,
} from '../config-scaffold.js'

describe('offerStashConfig (optional config scaffold)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-config-scaffold-'))
  })

  afterEach(() => {
    vi.restoreAllMocks()
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('non-interactively creates a config with the default client path', async () => {
    // Under vitest process.stdin.isTTY is undefined → the non-interactive branch
    // writes a config instead of prompting (which would hang in CI / agents).
    const clientPath = await offerStashConfig({ cwd: tmpDir })

    expect(clientPath).toBe(DEFAULT_CLIENT_PATH)
    const written = fs.readFileSync(path.join(tmpDir, CONFIG_FILENAME), 'utf-8')
    expect(written).toContain("from 'stash'")
    expect(written).toContain(`client: '${DEFAULT_CLIENT_PATH}'`)
  })

  it('ensure mode creates the config (init path)', async () => {
    // `ensure` is how `stash init` requests a config unconditionally; it must
    // write one regardless of the prompt path.
    const clientPath = await offerStashConfig({ ensure: true, cwd: tmpDir })

    expect(clientPath).toBe(DEFAULT_CLIENT_PATH)
    expect(fs.existsSync(path.join(tmpDir, CONFIG_FILENAME))).toBe(true)
  })

  it('points the config at a detected client file when one exists', async () => {
    fs.mkdirSync(path.join(tmpDir, 'src'))
    fs.writeFileSync(path.join(tmpDir, 'src', 'encryption.ts'), '// client')

    const clientPath = await offerStashConfig({ cwd: tmpDir })

    expect(clientPath).toBe('./src/encryption.ts')
    expect(
      fs.readFileSync(path.join(tmpDir, CONFIG_FILENAME), 'utf-8'),
    ).toContain(`client: './src/encryption.ts'`)
  })

  it('never overwrites an existing config', async () => {
    const configPath = path.join(tmpDir, CONFIG_FILENAME)
    fs.writeFileSync(configPath, '// hand-written, do not touch')

    const clientPath = await offerStashConfig({ cwd: tmpDir })

    expect(clientPath).toBe(DEFAULT_CLIENT_PATH)
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(
      '// hand-written, do not touch',
    )
  })
})
