import { describe, expect, it } from 'vitest'
import { parseArgs } from '../bin/parse-args.js'

// `parseArgs` takes the full process.argv (node + script + args), so the
// test shapes its inputs the same way: ['node', 'wizard.js', ...flags].
function argv(...flags: string[]): string[] {
  return ['node', 'wizard.js', ...flags]
}

describe('wizard parseArgs — mode resolution', () => {
  it('defaults to implement when no mode flag is passed', () => {
    expect(parseArgs(argv()).mode).toBe('implement')
    // --debug alone shouldn't change mode
    expect(parseArgs(argv('--debug')).mode).toBe('implement')
  })

  it('accepts the --plan shortcut', () => {
    expect(parseArgs(argv('--plan')).mode).toBe('plan')
  })

  it('accepts the --implement shortcut (no-op against the default)', () => {
    expect(parseArgs(argv('--implement')).mode).toBe('implement')
  })

  it('accepts --mode plan (space-separated long form)', () => {
    expect(parseArgs(argv('--mode', 'plan')).mode).toBe('plan')
    expect(parseArgs(argv('--mode', 'implement')).mode).toBe('implement')
  })

  it('accepts --mode=plan (equals-separated long form)', () => {
    expect(parseArgs(argv('--mode=plan')).mode).toBe('plan')
    expect(parseArgs(argv('--mode=implement')).mode).toBe('implement')
  })

  it('rejects unknown --mode values with a clear error', () => {
    const result = parseArgs(argv('--mode', 'yolo'))
    expect(result.modeError).toMatch(/Unknown --mode value/)
    expect(result.modeError).toMatch(/yolo/)
  })

  it('rejects unknown --mode= values with a clear error', () => {
    const result = parseArgs(argv('--mode=yolo'))
    expect(result.modeError).toMatch(/Unknown --mode value/)
  })

  it('rejects --mode at the end of argv with a clear error (regression: silent fall-through)', () => {
    // Without the trailing-value guard, `--mode` as the final arg falls
    // through to the default `implement` with no diagnostic — strictly
    // worse than `--mode=` (which already errors). Both forms now surface
    // the same "requires a value" error.
    const result = parseArgs(argv('--mode'))
    expect(result.modeError).toMatch(/--mode requires a value/)
  })

  it('lets the last mode flag win when multiple are passed', () => {
    // Useful for wrappers that always append a mode flag — they don't have
    // to detect and remove an earlier one.
    expect(parseArgs(argv('--plan', '--implement')).mode).toBe('implement')
    expect(parseArgs(argv('--implement', '--plan')).mode).toBe('plan')
    expect(parseArgs(argv('--mode', 'plan', '--implement')).mode).toBe(
      'implement',
    )
    expect(parseArgs(argv('--implement', '--mode=plan')).mode).toBe('plan')
  })

  it('threads --debug independently of mode flags', () => {
    expect(parseArgs(argv('--plan', '--debug')).debug).toBe(true)
    expect(parseArgs(argv('--debug', '--plan')).mode).toBe('plan')
  })

  it('exposes --help and --version flags independently', () => {
    expect(parseArgs(argv('--help')).help).toBe(true)
    expect(parseArgs(argv('-h')).help).toBe(true)
    expect(parseArgs(argv('--version')).version).toBe(true)
    expect(parseArgs(argv('-v')).version).toBe(true)
  })
})
