import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ensureConfigDependencies,
  missingConfigDependencies,
} from '../config-scaffold.js'

/** Create a fake installed package under `<cwd>/node_modules/<name>`. */
function fakeInstall(cwd: string, name: string): void {
  const dir = path.join(cwd, 'node_modules', name)
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name }))
}

describe('config-scaffold dependency guard', () => {
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

  describe('missingConfigDependencies', () => {
    it('reports both packages missing in a bare project', () => {
      expect(missingConfigDependencies(tmpDir)).toEqual({
        prod: ['@cipherstash/stack'],
        dev: ['stash'],
      })
    })

    it('reports nothing missing when both are installed', () => {
      fakeInstall(tmpDir, 'stash')
      fakeInstall(tmpDir, '@cipherstash/stack')
      expect(missingConfigDependencies(tmpDir)).toEqual({ prod: [], dev: [] })
    })

    it('reports only the package that is actually missing', () => {
      fakeInstall(tmpDir, '@cipherstash/stack')
      expect(missingConfigDependencies(tmpDir)).toEqual({
        prod: [],
        dev: ['stash'],
      })
    })
  })

  describe('ensureConfigDependencies', () => {
    it('returns true (no prompt) when both packages are present', async () => {
      fakeInstall(tmpDir, 'stash')
      fakeInstall(tmpDir, '@cipherstash/stack')
      await expect(ensureConfigDependencies(tmpDir)).resolves.toBe(true)
    })

    it('warns and returns false in non-interactive contexts when deps are missing (#579)', async () => {
      // Under vitest, process.stdin.isTTY is undefined → the guard takes the
      // non-interactive branch: it must print guidance and stop cleanly rather
      // than spawn a package manager or hang on a prompt. Capture stdout (where
      // clack writes) to assert the guidance surfaced.
      let out = ''
      vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
        out += String(chunk)
        return true
      })

      await expect(ensureConfigDependencies(tmpDir)).resolves.toBe(false)
      expect(out).toContain('not installed')
      expect(out).toContain('stash init')
    })
  })
})
