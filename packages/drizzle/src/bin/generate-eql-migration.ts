import { execSync } from 'node:child_process'
import { existsSync, unlinkSync, writeFileSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { detectRunner } from './runner.js'

// EQL release, pinned to match the EQL payload format this package emits.
// Bump in lockstep with @cipherstash/protect-ffi.
const EQL_VERSION = 'eql-2.2.1'
const EQL_INSTALL_URL =
  `https://github.com/cipherstash/encrypt-query-language/releases/download/${EQL_VERSION}/cipherstash-encrypt.sql`

type CliArgs = {
  migrationName: string
  drizzleDir: string
  showHelp: boolean
}

function parseArgs(argv: string[]): CliArgs {
  let migrationName = 'install-eql'
  let drizzleDir = 'drizzle'
  let showHelp = false

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      showHelp = true
    } else if (arg === '--name' || arg === '-n') {
      migrationName = argv[++i] ?? migrationName
    } else if (arg === '--out' || arg === '-o') {
      drizzleDir = argv[++i] ?? drizzleDir
    }
  }

  return { migrationName, drizzleDir, showHelp }
}

function printHelp(runner: string): void {
  console.log(`
Usage: generate-eql-migration [options]

Generate a Drizzle migration that installs CipherStash EQL

Options:
  -n, --name <name>    Migration name (default: "install-eql")
  -o, --out <dir>      Output directory (default: "drizzle")
  -h, --help           Display this help message

Examples:
  ${runner} generate-eql-migration
  ${runner} generate-eql-migration --name setup-eql
  ${runner} generate-eql-migration --out migrations

  # Or with your package manager:
  pnpm generate-eql-migration
  yarn generate-eql-migration
  bun generate-eql-migration
`)
}

async function main(): Promise<void> {
  let migrationPath: string | null = null
  const args = parseArgs(process.argv.slice(2))
  const runner = detectRunner()

  if (args.showHelp) {
    printHelp(runner)
    process.exit(0)
  }

  console.log('🔐 Generating EQL migration for Drizzle...\n')

  try {
    console.log(`📝 Generating custom migration: ${args.migrationName}`)
    execSync(`${runner} drizzle-kit generate --custom --name=${args.migrationName}`, {
      stdio: 'inherit',
    })
  } catch (error) {
    console.error('❌ Failed to generate custom migration')
    console.error('Make sure drizzle-kit is installed in your project.')
    process.exit(1)
  }

  try {
    console.log(`📥 Downloading latest EQL from GitHub...`)
    const response = await fetch(EQL_INSTALL_URL)
    if (!response.ok) {
      throw new Error(`Failed to download EQL: ${response.status} ${response.statusText}`)
    }
    const eqlSql = await response.text()

    const drizzlePath = resolve(process.cwd(), args.drizzleDir)

    let files: string[]
    try {
      files = await readdir(drizzlePath)
    } catch {
      throw new Error(
        `Drizzle directory not found: ${drizzlePath}\nMake sure to run this command from your project root.`,
      )
    }
    const migrationFile = files
      .filter(
        (file) => file.endsWith('.sql') && file.includes(args.migrationName),
      )
      .sort()
      .pop()

    if (!migrationFile) {
      throw new Error(
        `Could not find migration file for: ${args.migrationName}\nLooked in: ${drizzlePath}`,
      )
    }

    migrationPath = join(drizzlePath, migrationFile)
    console.log(`\n📄 Writing EQL SQL to: ${migrationFile}`)

    writeFileSync(migrationPath, eqlSql, 'utf-8')

    console.log('\n✅ Successfully created EQL migration!')
    console.log('\nNext steps:')
    console.log(`  1. Review the migration: ${migrationPath}`)
    console.log(`  2. Run migrations: ${runner} drizzle-kit migrate`)
    console.log(
      '     (or use your package manager: pnpm/yarn/bun drizzle-kit migrate)',
    )
  } catch (error) {
    if (migrationPath && existsSync(migrationPath)) {
      try {
        unlinkSync(migrationPath)
        console.error(`\n🗑️  Cleaned up migration file: ${migrationPath}`)
      } catch (cleanupError) {
        console.error(`\n⚠️  Failed to cleanup migration file: ${migrationPath}`)
      }
    }
    throw error
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error)
  console.error('❌ Error:', message)
  process.exit(1)
})
