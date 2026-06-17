import { existsSync, statSync } from 'node:fs'
import { platform } from 'node:os'
import { delimiter, resolve } from 'node:path'

export type Editor = 'vscode' | 'cursor' | 'unknown'

export interface AgentEnvironment {
  cli: {
    /** `claude` is on PATH. */
    claudeCode: boolean
    /** `codex` is on PATH. */
    codex: boolean
  }
  project: {
    /** A `.claude/` directory exists at the project root. */
    claudeDir: boolean
    /** A `CLAUDE.md` file exists at the project root. */
    claudeMd: boolean
    /** A `.claude/skills/` directory exists at the project root. */
    claudeSkillsDir: boolean
    /** An `AGENTS.md` file exists at the project root. */
    agentsMd: boolean
  }
  /** Which editor is hosting the current terminal, if recognisable. */
  editor: Editor
}

/**
 * Walk `PATH` looking for an executable. Pure-Node lookup so we don't
 * depend on `/bin/sh -c command -v` (POSIX-only) or `where` (Windows-only).
 * Allowlists the bin name to a conservative pattern — a defensive
 * belt-and-braces given callers only pass closed-enum literals today.
 */
function isOnPath(bin: string, env: NodeJS.ProcessEnv): boolean {
  if (!/^[a-z0-9_-]+$/i.test(bin)) return false
  const path = env.PATH ?? env.Path ?? env.path ?? ''
  if (!path) return false

  const isWindows = platform() === 'win32'
  // PATHEXT lets us match `claude.cmd` / `claude.exe` on Windows; on POSIX we
  // only look for the bare name. We don't honour `process.env.PATHEXT` for
  // arbitrary user-set casing — `.cmd`, `.exe`, `.bat` cover ~99% of installs.
  const exts = isWindows ? ['.cmd', '.exe', '.bat', ''] : ['']

  for (const dir of path.split(delimiter)) {
    if (!dir) continue
    for (const ext of exts) {
      const candidate = resolve(dir, `${bin}${ext}`)
      if (existsSync(candidate)) return true
    }
  }
  return false
}

function detectEditor(env: NodeJS.ProcessEnv): Editor {
  if (env.CURSOR_TRACE_ID) return 'cursor'
  if (env.TERM_PROGRAM === 'vscode') return 'vscode'
  return 'unknown'
}

function isDirectory(path: string): boolean {
  if (!existsSync(path)) return false
  try {
    return statSync(path).isDirectory()
  } catch {
    return false
  }
}

/**
 * Detect available coding agents and editor context.
 *
 * `cwd` and `env` are injected so tests can mock them; production callers can
 * use the no-arg form.
 */
export function detectAgents(
  cwd: string = process.cwd(),
  env: NodeJS.ProcessEnv = process.env,
): AgentEnvironment {
  return {
    cli: {
      claudeCode: isOnPath('claude', env),
      codex: isOnPath('codex', env),
    },
    project: {
      claudeDir: isDirectory(resolve(cwd, '.claude')),
      claudeMd: existsSync(resolve(cwd, 'CLAUDE.md')),
      claudeSkillsDir: isDirectory(resolve(cwd, '.claude', 'skills')),
      agentsMd: existsSync(resolve(cwd, 'AGENTS.md')),
    },
    editor: detectEditor(env),
  }
}

/**
 * Convenience predicate. The handoff offer in the init flow wants to know
 * "should we default to Claude Code?", which collapses CLI presence + any
 * project-level Claude artifact into a single yes/no.
 */
export function shouldOfferClaudeCode(env: AgentEnvironment): boolean {
  return env.cli.claudeCode
}
