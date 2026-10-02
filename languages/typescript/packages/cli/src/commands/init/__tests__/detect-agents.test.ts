import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { detectAgents, shouldOfferClaudeCode } from '../detect-agents.js'

describe('detectAgents', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'detect-agents-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('reports no project artifacts in a fresh directory', () => {
    const env = detectAgents(tmp, {})
    expect(env.project.claudeDir).toBe(false)
    expect(env.project.claudeMd).toBe(false)
    expect(env.project.claudeSkillsDir).toBe(false)
    expect(env.project.agentsMd).toBe(false)
  })

  it('detects CLAUDE.md, .claude/, and .claude/skills/', () => {
    writeFileSync(join(tmp, 'CLAUDE.md'), 'hi')
    mkdirSync(join(tmp, '.claude', 'skills'), { recursive: true })

    const env = detectAgents(tmp, {})
    expect(env.project.claudeMd).toBe(true)
    expect(env.project.claudeDir).toBe(true)
    expect(env.project.claudeSkillsDir).toBe(true)
  })

  it('detects AGENTS.md at the project root', () => {
    writeFileSync(join(tmp, 'AGENTS.md'), '# project rules\n')
    const env = detectAgents(tmp, {})
    expect(env.project.agentsMd).toBe(true)
  })

  it('exposes both claudeCode and codex as boolean fields on cli', () => {
    const env = detectAgents(tmp, {})
    expect(typeof env.cli.claudeCode).toBe('boolean')
    expect(typeof env.cli.codex).toBe('boolean')
  })

  it('classifies the editor from env signals', () => {
    expect(detectAgents(tmp, { CURSOR_TRACE_ID: 'abc' }).editor).toBe('cursor')
    expect(detectAgents(tmp, { TERM_PROGRAM: 'vscode' }).editor).toBe('vscode')
    expect(detectAgents(tmp, {}).editor).toBe('unknown')
  })

  it('shouldOfferClaudeCode follows CLI presence', () => {
    const env = detectAgents(tmp, {})
    // We can't reliably mock command -v from a unit test, so just assert the
    // helper reads the field without throwing.
    expect(typeof shouldOfferClaudeCode(env)).toBe('boolean')
    expect(shouldOfferClaudeCode(env)).toBe(env.cli.claudeCode)
  })
})
