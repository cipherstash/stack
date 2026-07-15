import { describe, expect, it } from 'vitest'
import { classifyCommand } from '../classify-command.js'

describe('classifyCommand (telemetry value allowlist)', () => {
  it('keeps a recognised command + subcommand path', () => {
    expect(classifyCommand('eql', 'install')).toEqual({
      command: 'eql',
      subcommand: 'install',
    })
    expect(classifyCommand('auth', 'login')).toEqual({
      command: 'auth',
      subcommand: 'login',
    })
  })

  it('keeps a recognised command with no subcommand', () => {
    expect(classifyCommand('init', undefined)).toEqual({
      command: 'init',
      subcommand: undefined,
    })
  })

  it('keeps the telemetry sub-verbs (not in the registry, but known-safe)', () => {
    for (const verb of ['status', 'enable', 'disable']) {
      expect(classifyCommand('telemetry', verb)).toEqual({
        command: 'telemetry',
        subcommand: verb,
      })
    }
  })

  it('coerces a free-text positional to <other> — the wizard-prompt leak', () => {
    // The core fix: `stash wizard "add encryption to patients.ssn"` must never
    // send the prompt (which carries table/column names) as the subcommand value.
    expect(
      classifyCommand('wizard', 'add searchable encryption to patients.ssn'),
    ).toEqual({ command: 'wizard', subcommand: '<other>' })
  })

  it('keeps the command but drops an unrecognised subcommand to <other>', () => {
    expect(classifyCommand('eql', 'rm -rf /')).toEqual({
      command: 'eql',
      subcommand: '<other>',
    })
  })

  it('coerces an entirely unknown command to <other> and drops its subcommand', () => {
    expect(classifyCommand('definitely-not-a-command', 'secret-value')).toEqual(
      {
        command: '<other>',
        subcommand: undefined,
      },
    )
  })
})
