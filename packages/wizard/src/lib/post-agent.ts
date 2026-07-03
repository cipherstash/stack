/**
 * Post-agent CLI steps.
 *
 * Runs deterministic commands after the agent finishes editing code.
 * These don't need AI — they're fixed commands we can run directly.
 */

import { execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import type { GatheredContext } from './gather.js'
import { rewriteEncryptedAlterColumns } from './rewrite-migrations.js'
import type { DetectedPackageManager, Integration } from './types.js'

interface PostAgentOptions {
  cwd: string
  integration: Integration
  gathered: GatheredContext
  packageManager: DetectedPackageManager | undefined
}

/**
 * Candidate directories drizzle-kit may write migrations to. We check in
 * order and rewrite the first one that exists; `drizzle` is the default.
 */
const DRIZZLE_OUT_DIRS = ['drizzle', 'migrations', 'src/db/migrations']

/**
 * Run all post-agent steps: install packages, push config, run migrations.
 */
export async function runPostAgentSteps(opts: PostAgentOptions): Promise<void> {
  const { cwd, integration, gathered, packageManager } = opts
  const runner = packageManager?.execCommand ?? 'npx'

  // Step 1: Install @cipherstash/stack
  await runStep(
    'Installing @cipherstash/stack...',
    'Package installed',
    gathered.installCommand,
    cwd,
  )

  // Step 2: Run runner stash eql install if the project doesn't yet
  // have a stash.config.ts. `eql install` scaffolds the config and installs
  // EQL in a single step (CIP-2986).
  if (!gathered.hasStashConfig) {
    await runStep(
      `Running ${runner} stash eql install...`,
      `${runner} stash eql install complete`,
      `${runner} stash eql install`,
      cwd,
    )
  }

  // Step 3: Push encryption config (only when using Proxy)
  if (gathered.usesProxy) {
    await runStep(
      'Pushing encryption config to database...',
      'Encryption config pushed',
      `${runner} stash db push`,
      cwd,
    )
  } else {
    p.log.info(
      'Skipping `stash db push` — not using CipherStash Proxy. Run it manually if you ever switch to Proxy.',
    )
  }

  // Step 4: Integration-specific migrations
  if (integration === 'drizzle') {
    await runStep(
      'Generating Drizzle migration...',
      'Migration generated',
      `${runner} drizzle-kit generate`,
      cwd,
    )

    // Rewrite any `ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted` that
    // drizzle-kit just produced — those fail in Postgres. CIP-2991 + CIP-2994.
    await rewriteEncryptedMigrations(cwd)

    const shouldMigrate = await p.confirm({
      message: `Run the migration now? (${runner} drizzle-kit migrate)`,
      initialValue: true,
    })

    if (!p.isCancel(shouldMigrate) && shouldMigrate) {
      await runStep(
        'Running migration...',
        'Migration complete',
        `${runner} drizzle-kit migrate`,
        cwd,
      )
    }
  }

  if (integration === 'prisma') {
    const shouldMigrate = await p.confirm({
      message: `Run Prisma migration now? (${runner} prisma migrate dev --name add-encryption)`,
      initialValue: true,
    })

    if (!p.isCancel(shouldMigrate) && shouldMigrate) {
      await runStep(
        'Running Prisma migration...',
        'Migration complete',
        `${runner} prisma migrate dev --name add-encryption`,
        cwd,
      )
    }
  }
}

async function rewriteEncryptedMigrations(cwd: string): Promise<void> {
  for (const dir of DRIZZLE_OUT_DIRS) {
    const abs = resolve(cwd, dir)
    if (!existsSync(abs)) continue

    try {
      const rewritten = await rewriteEncryptedAlterColumns(abs)
      if (rewritten.length > 0) {
        p.log.info(
          `Rewrote ${rewritten.length} migration file(s) in ${dir}/ to use ADD+DROP+RENAME for encrypted columns.`,
        )
        for (const file of rewritten) p.log.step(`  - ${file}`)
        p.log.warn(
          'If any of these tables already have rows, backfill the new column via @cipherstash/stack before running the migration in production. See the comments in the rewritten SQL.',
        )
      }
      // Only rewrite the first dir that matches — running again on a
      // different candidate would double-transform already-rewritten SQL.
      return
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      p.log.warn(`Could not rewrite migrations in ${dir}: ${message}`)
      return
    }
  }
}

async function runStep(
  startMsg: string,
  doneMsg: string,
  command: string,
  cwd: string,
): Promise<void> {
  const s = p.spinner()
  s.start(startMsg)
  try {
    execSync(command, {
      cwd,
      stdio: 'pipe',
      timeout: 120_000,
    })
    s.stop(doneMsg)
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error'
    s.stop(`Failed: ${command}`)
    p.log.warn(`Command failed: ${message}`)
    p.log.info(`You can run this manually: ${command}`)
  }
}
