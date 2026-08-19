import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import * as p from '@clack/prompts'
import { DEFAULT_CLIENT_PATH } from '../../../config/index.js'
import { isInteractive } from '../../../config/tty.js'
import {
  detectDrizzle,
  detectPrismaNext,
  detectSupabase,
} from '../../db/detect.js'
import { readEnvKeyNames } from '../lib/env-keys.js'
import { writeBaselineContextFile } from '../lib/write-context.js'
import type {
  InitProvider,
  InitState,
  InitStep,
  Integration,
} from '../types.js'
import { CancelledError } from '../types.js'
import { generatePlaceholderClient } from '../utils.js'
import { topUpSkills } from './install-skills.js'

/**
 * Pick the integration template by reading the same signals `eql install`
 * uses — Drizzle config / dependency for `drizzle`, Supabase host in
 * `DATABASE_URL` for `supabase`, otherwise raw Postgres. Silent: never
 * prompts the user.
 */
function detectIntegration(
  cwd: string,
  databaseUrl: string | undefined,
): Integration {
  // Prisma Next is checked first: a project can use Prisma Next on top
  // of a Supabase-hosted database, in which case both signals fire but
  // the migration framework belongs to Prisma Next and that's what
  // drives the install path.
  if (detectPrismaNext(cwd)) return 'prisma-next'
  if (detectDrizzle(cwd)) return 'drizzle'
  if (detectSupabase(databaseUrl)) return 'supabase'
  return 'postgresql'
}

/**
 * Write a placeholder encryption client to `src/encryption/index.ts`.
 *
 * Init no longer introspects the database to generate a parallel
 * encryption client. The user's existing schema files (Drizzle / Supabase /
 * raw SQL migrations) remain the authoritative source. The placeholder is a
 * heavily-commented file showing the encryption-client patterns; the agent
 * at handoff time edits the user's real schema files directly and updates
 * the `Encryption({ schemas: [...] })` call in this file to reference them.
 *
 * Why no column picker: deciding which columns to encrypt is the user's
 * choice in conversation with their agent, not a question to answer at
 * init time. Path 1 (new column) and path 3 (existing populated column —
 * lifecycle migration via `stash encrypt`) need different treatment, and
 * init can't tell which the user wants.
 */
export const buildSchemaStep: InitStep = {
  id: 'build-schema',
  name: 'Generate encryption client',
  async run(state: InitState, provider: InitProvider): Promise<InitState> {
    const cwd = process.cwd()
    // `provider.selected`, not `provider.name`: a combined run
    // (`--prisma --supabase`) names itself 'prisma-supabase', so an equality
    // test here dropped it onto `detectIntegration` — which, on a project whose
    // prisma-next config isn't in place yet, answers 'postgresql' and sends the
    // rest of the pipeline down the wrong route.
    const integration = provider.selected.includes('prisma')
      ? 'prisma-next'
      : detectIntegration(cwd, state.databaseUrl)
    const clientFilePath = DEFAULT_CLIENT_PATH
    const resolvedPath = resolve(cwd, clientFilePath)

    // Prisma Next derives the stack-side schema from `contract.json`
    // via `cipherstashFromStack({ contractJson })` at runtime — there
    // is no hand-written `src/encryption/index.ts` to scaffold. Skip
    // the placeholder step and let the framework drive the schema
    // surface.
    if (integration === 'prisma-next') {
      p.log.success(
        'Skipping encryption-client scaffold — Prisma Next derives schemas from contract.json via `cipherstashFromStack({ contractJson })`.',
      )

      const envKeys = readEnvKeyNames(cwd)
      const nextState: InitState = {
        ...state,
        schemaGenerated: false,
        integration,
        schemas: [],
        schemaFromIntrospection: false,
        envKeys,
        skills: topUpSkills(cwd, state, integration),
      }
      writeBaselineContextFile(nextState, cwd, envKeys)
      return nextState
    }

    // Existing-file branch: silent overwrite is bad. Ask once.
    let keepExisting = false
    if (existsSync(resolvedPath)) {
      // Non-interactive (CI, agents, pipes): keep the existing file rather than
      // prompt. Keeping is the safe default — never clobber the user's client
      // without an explicit answer.
      if (!isInteractive()) {
        keepExisting = true
        p.log.info(
          `${clientFilePath} already exists; keeping it (non-interactive).`,
        )
      } else {
        const action = await p.select({
          message: `${clientFilePath} already exists. What would you like to do?`,
          options: [
            {
              value: 'keep',
              label: 'Keep existing file',
              hint: 'skip code generation',
            },
            { value: 'overwrite', label: 'Overwrite with placeholder' },
          ],
        })

        if (p.isCancel(action)) throw new CancelledError()

        keepExisting = action === 'keep'
        if (keepExisting) p.log.info('Keeping existing encryption client file.')
      }
    }

    if (!keepExisting) {
      const dir = dirname(resolvedPath)
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
      writeFileSync(
        resolvedPath,
        generatePlaceholderClient(integration),
        'utf-8',
      )
      p.log.success(
        `Encryption client placeholder written to ${clientFilePath} (${integration}). Your real schema files remain authoritative.`,
      )
    }

    // Read env-key names once and put them on state. gather-context (later in
    // the pipeline) and the handoff steps all read from there rather than
    // re-scanning `.env*` files. Names only — never values.
    const envKeys = readEnvKeyNames(cwd)

    const nextState: InitState = {
      ...state,
      clientFilePath,
      schemaGenerated: !keepExisting,
      integration,
      schemas: [],
      // No longer meaningful — init never introspects-and-picks. Kept on
      // state for now to avoid a wider type change; always false.
      schemaFromIntrospection: false,
      envKeys,
      // The install-skills step ran before `DATABASE_URL` was resolved, so a
      // bare `stash init` against a Supabase-hosted database got the base
      // skill set. Now that `integration` is known, top it up — idempotent,
      // and a no-op when the first-step guess already matched.
      skills: topUpSkills(cwd, state, integration),
    }

    // Write a baseline `.cipherstash/context.json` immediately so it tracks
    // the placeholder we just wrote — including the skills installed by the
    // first step, so the file never claims `installedSkills: []` over a
    // project that has them (#923). Handoff steps merge their own delivery
    // in later; this baseline guarantees the file exists, and is honest,
    // even if init aborts before any handoff fires.
    writeBaselineContextFile(nextState, cwd, envKeys)

    return nextState
  },
}
