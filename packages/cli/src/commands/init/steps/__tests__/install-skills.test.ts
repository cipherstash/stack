import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AgentEnvironment } from '../../detect-agents.js'
import type { InitProvider, InitState } from '../../types.js'

vi.mock('@clack/prompts', () => ({
  log: { warn: vi.fn(), success: vi.fn(), info: vi.fn() },
}))

import {
  CLAUDE_SKILLS_DIR,
  CODEX_SKILLS_DIR,
  guessIntegration,
  installSkillsStep,
  skillDestinations,
  topUpSkills,
} from '../install-skills.js'

/** An environment with nothing detected; tests switch on what they need. */
function env(overrides: Partial<AgentEnvironment> = {}): AgentEnvironment {
  return {
    cli: { claudeCode: false, codex: false },
    project: {
      claudeDir: false,
      claudeMd: false,
      claudeSkillsDir: false,
      codexDir: false,
      agentsMd: false,
    },
    editor: 'unknown',
    ...overrides,
  }
}

function provider(selected: InitProvider['selected'] = []): InitProvider {
  return {
    name: 'test',
    selected,
    introMessage: '',
    getNextSteps: () => [],
  }
}

let cwd: string

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'stash-init-skills-'))
  vi.spyOn(process, 'cwd').mockReturnValue(cwd)
  // `installSkillsStep` calls the real `detectAgents`, which walks the real
  // PATH — so on a developer machine with `claude` installed every
  // "nothing detected" case would install anyway, and pass or fail by
  // accident of who ran it. Blank the PATH and drive detection from the
  // project-level signals the temp cwd controls.
  vi.stubEnv('PATH', '')
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  rmSync(cwd, { recursive: true, force: true })
})

describe('skillDestinations', () => {
  it('installs nowhere when no agent is detected', () => {
    expect(skillDestinations(env(), undefined)).toEqual([])
  })

  it('follows the Claude CLI', () => {
    expect(
      skillDestinations(
        env({ cli: { claudeCode: true, codex: false } }),
        undefined,
      ),
    ).toEqual([CLAUDE_SKILLS_DIR])
  })

  // The #923 flow: an agent running `npx stash init` inside a repo that
  // already has `.claude/`. The binary need not be on the PATH this process
  // inherited for the project to be a Claude Code project.
  it('follows a project-level .claude/ with no CLI on PATH', () => {
    const agents = env()
    agents.project.claudeDir = true
    expect(skillDestinations(agents, undefined)).toEqual([CLAUDE_SKILLS_DIR])
  })

  it('follows a project-level .codex/', () => {
    const agents = env()
    agents.project.codexDir = true
    expect(skillDestinations(agents, undefined)).toEqual([CODEX_SKILLS_DIR])
  })

  it('installs both when both are detected', () => {
    expect(
      skillDestinations(
        env({ cli: { claudeCode: true, codex: true } }),
        undefined,
      ),
    ).toEqual([CLAUDE_SKILLS_DIR, CODEX_SKILLS_DIR])
  })

  // An explicit --target is the user naming their agent. Detection must not
  // add a second directory they did not ask for.
  it('honours --target over detection, without adding the detected one', () => {
    expect(
      skillDestinations(
        env({ cli: { claudeCode: true, codex: false } }),
        'codex',
      ),
    ).toEqual([CODEX_SKILLS_DIR])
  })

  // These handoffs inline the skill bodies into AGENTS.md instead of copying
  // directories, and `init` performs no handoff — so there is nothing to write.
  it.each([
    'agents-md',
    'lovable',
    'wizard',
  ] as const)('installs no directories for --target %s', (target) => {
    expect(
      skillDestinations(
        env({ cli: { claudeCode: true, codex: false } }),
        target,
      ),
    ).toEqual([])
  })
})

describe('guessIntegration', () => {
  it('is undefined when nothing is conclusive', () => {
    expect(guessIntegration(cwd, provider())).toBeUndefined()
  })

  it('reads the --supabase flag', () => {
    expect(guessIntegration(cwd, provider(['supabase']))).toBe('supabase')
  })

  // `build-schema`'s detectIntegration consults only `--prisma`, so a
  // `--drizzle` run in a project with no Drizzle config classifies as
  // postgresql there. For the encryption client that is right; for skills it
  // is not — the flag is the user naming the integration to teach the agent,
  // and ignoring it hands them the base set instead of the Drizzle one.
  it('reads the --drizzle flag even with no drizzle config on disk', () => {
    expect(guessIntegration(cwd, provider(['drizzle']))).toBe('drizzle')
  })

  // Same precedence init uses when routing the EQL migration: Drizzle owns
  // the migration history, `--supabase` is the grants modifier.
  it('prefers drizzle over supabase on a combined run', () => {
    expect(guessIntegration(cwd, provider(['supabase', 'drizzle']))).toBe(
      'drizzle',
    )
  })

  // Same precedence as build-schema's detectIntegration: Prisma Next owns the
  // migration framework even when a Supabase signal also fires.
  it('prefers prisma-next over supabase on a combined run', () => {
    expect(guessIntegration(cwd, provider(['supabase', 'prisma']))).toBe(
      'prisma-next',
    )
  })
})

describe('installSkillsStep', () => {
  it('copies skills into .claude/skills and records them on state', async () => {
    mkdirSync(join(cwd, '.claude'), { recursive: true })

    const next = await installSkillsStep.run({}, provider(['supabase']))

    expect(next.skills?.installed).toContain('stash-supabase')
    expect(next.skills?.installed).toContain('stash-cli')
    expect(next.skills?.failed).toEqual([])
    expect(
      existsSync(join(cwd, CLAUDE_SKILLS_DIR, 'stash-supabase', 'SKILL.md')),
    ).toBe(true)
  })

  // The base set is what an unclassifiable run gets — a bare `stash init`
  // whose Supabase-ness lives in a DATABASE_URL that has not been resolved
  // yet. It must still carry `stash-cli`, the skill covering recovery from
  // the auth / database / EQL failures this step now runs ahead of.
  it('falls back to the base skill set when the integration is unknown', async () => {
    mkdirSync(join(cwd, '.claude'), { recursive: true })

    const next = await installSkillsStep.run({}, provider())

    expect(next.skills?.installed).toContain('stash-cli')
    expect(next.skills?.installed).not.toContain('stash-supabase')
  })

  it('installs the flagged integration set, not just the base set', async () => {
    mkdirSync(join(cwd, '.claude'), { recursive: true })

    const next = await installSkillsStep.run({}, provider(['drizzle']))

    expect(next.skills?.installed).toContain('stash-drizzle')
  })

  it('installs nothing and stays non-fatal when no agent is detected', async () => {
    const next = await installSkillsStep.run({}, provider(['supabase']))

    expect(next.skills?.installed).toEqual([])
    expect(existsSync(join(cwd, '.claude'))).toBe(false)
    expect(existsSync(join(cwd, '.codex'))).toBe(false)
  })

  it('stores the detected environment so later steps do not re-walk PATH', async () => {
    const next = await installSkillsStep.run({}, provider())
    expect(next.agents).toBeDefined()
  })
})

describe('topUpSkills', () => {
  // The correction path for a bare `stash init` against a Supabase-hosted
  // URL: the first step could not classify it, `build-schema` can.
  it('adds the integration skills the base set was missing', async () => {
    mkdirSync(join(cwd, '.claude'), { recursive: true })
    const state = (await installSkillsStep.run({}, provider())) as InitState

    expect(state.skills?.installed).not.toContain('stash-supabase')

    const topped = topUpSkills(cwd, state, 'supabase')

    expect(topped?.installed).toContain('stash-supabase')
    expect(topped?.installed).toContain('stash-cli')
    // Merged, not replaced — every name appears once.
    expect(new Set(topped?.installed).size).toBe(topped?.installed.length)
  })

  it('is a no-op when the first-step guess already matched', async () => {
    mkdirSync(join(cwd, '.claude'), { recursive: true })
    const state = (await installSkillsStep.run(
      {},
      provider(['supabase']),
    )) as InitState

    expect(topUpSkills(cwd, state, 'supabase')?.installed).toEqual(
      state.skills?.installed,
    )
  })

  it('installs nothing when no agent was detected', async () => {
    const state = (await installSkillsStep.run({}, provider())) as InitState
    expect(topUpSkills(cwd, state, 'supabase')?.installed).toEqual([])
  })
})
