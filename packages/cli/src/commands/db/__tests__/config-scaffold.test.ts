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

  it('ensure mode creates the config with the default client path (init path)', async () => {
    // `ensure` is how `stash init` requests a config unconditionally; it must
    // write one without prompting.
    const clientPath = await offerStashConfig({ ensure: true, cwd: tmpDir })

    expect(clientPath).toBe(DEFAULT_CLIENT_PATH)
    const written = fs.readFileSync(path.join(tmpDir, CONFIG_FILENAME), 'utf-8')
    expect(written).toContain("from 'stash'")
    expect(written).toContain(`client: '${DEFAULT_CLIENT_PATH}'`)
  })

  it('ensure mode points the config at a detected client file when one exists', async () => {
    fs.mkdirSync(path.join(tmpDir, 'src'))
    fs.writeFileSync(path.join(tmpDir, 'src', 'encryption.ts'), '// client')

    const clientPath = await offerStashConfig({ ensure: true, cwd: tmpDir })

    expect(clientPath).toBe('./src/encryption.ts')
    expect(
      fs.readFileSync(path.join(tmpDir, CONFIG_FILENAME), 'utf-8'),
    ).toContain(`client: './src/encryption.ts'`)
  })

  it('offer mode writes nothing and returns null in a non-interactive context (#2, #4)', async () => {
    // Under vitest process.stdin.isTTY is undefined → non-interactive. Without
    // `ensure`, offer must NOT silently drop a config into the project, and the
    // null return is what makes the caller skip the client scaffold too.
    const clientPath = await offerStashConfig({ cwd: tmpDir })

    expect(clientPath).toBeNull()
    expect(fs.existsSync(path.join(tmpDir, CONFIG_FILENAME))).toBe(false)
  })

  it('never overwrites an existing config (returns null)', async () => {
    const configPath = path.join(tmpDir, CONFIG_FILENAME)
    fs.writeFileSync(configPath, '// hand-written, do not touch')

    const clientPath = await offerStashConfig({ cwd: tmpDir })

    expect(clientPath).toBeNull()
    expect(fs.readFileSync(configPath, 'utf-8')).toBe(
      '// hand-written, do not touch',
    )
  })
})
