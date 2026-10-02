import { describe, expect, it } from 'vitest'
import { classifyCommand, classifyErrorType } from '../classify-command.js'

describe('classifyErrorType (telemetry value allowlist)', () => {
  it('passes builtins and first-party error class names through', () => {
    expect(classifyErrorType(new TypeError('x'))).toBe('TypeError')
    expect(classifyErrorType(new Error('x'))).toBe('Error')
  })

  it('collapses a user-defined error class name to <other>', () => {
    // The CLI runs user code in-process (stash.config.ts via jiti); a class
    // named after a table/column must not leave inside errorType.
    class PatientsSsnColumnMissingError extends Error {}
    expect(classifyErrorType(new PatientsSsnColumnMissingError('x'))).toBe(
      '<other>',
    )
  })

  it('collapses non-Error throws to <other>', () => {
    expect(classifyErrorType('a thrown string')).toBe('<other>')
    expect(classifyErrorType(undefined)).toBe('<other>')
  })
})

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
