import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { detectDrizzle, detectSupabase } from '../commands/db/detect.js'

describe('detectSupabase', () => {
  it.each([
    ['postgres://user:pass@db.abc.supabase.co:5432/postgres', true],
    ['postgres://user:pass@db.abc.supabase.com:5432/postgres', true],
    [
      'postgres://user:pass@aws-0-us-east-1.pooler.supabase.com:6543/postgres',
      true,
    ],
    ['postgres://user:pass@localhost:5432/postgres', false],
    ['postgres://user:pass@db.neon.tech:5432/neondb', false],
    ['postgres://user:pass@ondemand.aws.neon.tech/neondb', false],
  ])('returns %s for %s', (url, expected) => {
    expect(detectSupabase(url)).toBe(expected)
  })

  it('returns false on undefined or malformed URLs', () => {
    expect(detectSupabase(undefined)).toBe(false)
    expect(detectSupabase('not a url')).toBe(false)
    expect(detectSupabase('')).toBe(false)
  })
})

describe('detectDrizzle', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-detect-drizzle-'))
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('returns true when a drizzle.config.ts exists', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'drizzle.config.ts'),
      'export default {}',
    )
    expect(detectDrizzle(tmpDir)).toBe(true)
  })

  it('returns true for drizzle.config.js', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'drizzle.config.js'),
      'module.exports = {}',
    )
    expect(detectDrizzle(tmpDir)).toBe(true)
  })

  it('returns true when package.json lists drizzle-orm', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ dependencies: { 'drizzle-orm': '^0.40.0' } }),
    )
    expect(detectDrizzle(tmpDir)).toBe(true)
  })

  it('returns true when package.json lists drizzle-kit as devDep', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ devDependencies: { 'drizzle-kit': '^0.30.0' } }),
    )
    expect(detectDrizzle(tmpDir)).toBe(true)
  })

  it('returns false when nothing indicates drizzle', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ dependencies: { prisma: '^5.0.0' } }),
    )
    expect(detectDrizzle(tmpDir)).toBe(false)
  })

  it('returns false on an empty directory', () => {
    expect(detectDrizzle(tmpDir)).toBe(false)
  })

  it('tolerates an unreadable package.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), '{ not valid json')
    expect(detectDrizzle(tmpDir)).toBe(false)
  })
})
