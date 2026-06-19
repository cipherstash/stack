import { config } from 'dotenv'

config()

import readline from 'node:readline'
import {
  buildApplication,
  buildCommand,
  buildRouteMap,
  run,
} from '@stricli/core'
import { Stash } from '../stash/index.js'
import { detectRunner } from './runner.js'

// ANSI color codes for beautiful terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
}

const style = {
  success: (text: string) =>
    `${colors.green}${colors.bold}✓${colors.reset} ${colors.green}${text}${colors.reset}`,
  error: (text: string) =>
    `${colors.red}${colors.bold}✗${colors.reset} ${colors.red}${text}${colors.reset}`,
  info: (text: string) =>
    `${colors.blue}${colors.bold}ℹ${colors.reset} ${colors.blue}${text}${colors.reset}`,
  warning: (text: string) =>
    `${colors.yellow}${colors.bold}⚠${colors.reset} ${colors.yellow}${text}${colors.reset}`,
  title: (text: string) => `${colors.bold}${colors.cyan}${text}${colors.reset}`,
  label: (text: string) => `${colors.dim}${text}${colors.reset}`,
  value: (text: string) => `${colors.bold}${text}${colors.reset}`,
  bullet: () => `${colors.green}•${colors.reset}`,
}

// Detect the package manager and build the CLI reference
const runner = detectRunner()
const cliRef = `${runner} stash`

/**
 * Get configuration from environment variables
 */
function getConfig(environment: string): Stash['config'] {
  const workspaceCRN = process.env.CS_WORKSPACE_CRN
  const clientId = process.env.CS_CLIENT_ID
  const clientKey = process.env.CS_CLIENT_KEY
  const apiKey = process.env.CS_CLIENT_ACCESS_KEY
  const accessKey = process.env.CS_ACCESS_KEY

  const missing: string[] = []
  if (!workspaceCRN) missing.push('CS_WORKSPACE_CRN')
  if (!clientId) missing.push('CS_CLIENT_ID')
  if (!clientKey) missing.push('CS_CLIENT_KEY')
  if (!apiKey) missing.push('CS_CLIENT_ACCESS_KEY')

  if (missing.length > 0) {
    console.error(
      style.error(
        `Missing required environment variables: ${missing.join(', ')}`,
      ),
    )
    console.error(
      `\n${style.info('Please set the following environment variables:')}`,
    )
    for (const varName of missing) {
      console.error(`  ${style.bullet()} ${varName}`)
    }
    process.exit(1)
  }

  if (!workspaceCRN || !clientId || !clientKey || !apiKey) {
    // This should never happen due to the check above, but TypeScript needs it
    throw new Error('Missing required configuration')
  }

  return {
    workspaceCRN,
    clientId,
    clientKey,
    apiKey,
    accessKey,
    environment,
  }
}

/**
 * Create a Stash instance with proper error handling
 */
function createStash(environment: string): Stash {
  const config = getConfig(environment)
  return new Stash(config)
}

/**
 * Prompt user for confirmation
 */
function askConfirmation(prompt: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  })

  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close()
      const normalized = answer.trim().toLowerCase()
      resolve(normalized === 'y' || normalized === 'yes')
    })
  })
}

/**
 * Set command - Store an encrypted secret
 */
const setCommand = buildCommand({
  func: async (flags: { name: string; value: string; environment: string }) => {
    const { name, value, environment } = flags
    const stash = createStash(environment)

    console.log(
      `${style.info(`Encrypting and storing secret "${name}" in environment "${environment}"...`)}`,
    )

    const result = await stash.set(name, value)
    if (result.failure) {
      console.error(
        style.error(`Failed to set secret: ${result.failure.message}`),
      )
      process.exit(1)
    }

    console.log(
      style.success(
        `Secret "${name}" stored successfully in environment "${environment}"`,
      ),
    )
  },
  parameters: {
    flags: {
      name: {
        kind: 'parsed',
        parse: String,
        brief: 'Name of the secret to store',
      },
      value: {
        kind: 'parsed',
        parse: String,
        brief: 'Plaintext value to encrypt and store',
      },
      environment: {
        kind: 'parsed',
        parse: String,
        brief: 'Environment name (e.g., production, staging, development)',
      },
    },
    aliases: {
      n: 'name',
      V: 'value',
      e: 'environment',
    },
  },
  docs: {
    brief: 'Store an encrypted secret in CipherStash',
    fullDescription: `
Store a secret value that will be encrypted locally before being sent to the CipherStash API.
The secret is encrypted end-to-end, ensuring your plaintext never leaves your machine unencrypted.

Examples:
  ${cliRef} secrets set --name DATABASE_URL --value "postgres://..." --environment production
  ${cliRef} secrets set -n DATABASE_URL -V "postgres://..." -e production
  ${cliRef} secrets set --name API_KEY --value "sk-123..." --environment staging
		`.trim(),
  },
})

/**
 * Get command - Retrieve and decrypt a secret
 */
const getCommand = buildCommand({
  func: async (flags: { name: string; environment: string }) => {
    const { name, environment } = flags
    const stash = createStash(environment)

    console.log(
      `${style.info(`Retrieving secret "${name}" from environment "${environment}"...`)}`,
    )

    const result = await stash.get(name)
    if (result.failure) {
      console.error(
        style.error(`Failed to get secret: ${result.failure.message}`),
      )
      process.exit(1)
    }

    console.log(`\n${style.title('Secret Value:')}`)
    console.log(style.value(result.data))
  },
  parameters: {
    flags: {
      name: {
        kind: 'parsed',
        parse: String,
        brief: 'Name of the secret to retrieve',
      },
      environment: {
        kind: 'parsed',
        parse: String,
        brief: 'Environment name (e.g., production, staging, development)',
      },
    },
    aliases: {
      n: 'name',
      e: 'environment',
    },
  },
  docs: {
    brief: 'Retrieve and decrypt a secret from CipherStash',
    fullDescription: `
Retrieve a secret from CipherStash and decrypt it locally. The secret value is decrypted
on your machine, ensuring end-to-end security.

Examples:
  ${cliRef} secrets get --name DATABASE_URL --environment production
  ${cliRef} secrets get -n DATABASE_URL -e production
  ${cliRef} secrets get --name API_KEY --environment staging
		`.trim(),
  },
})

/**
 * List command - List all secrets in an environment
 */
const listCommand = buildCommand({
  func: async (flags: { environment: string }) => {
    const { environment } = flags
    const stash = createStash(environment)

    console.log(
      `${style.info(`Listing secrets in environment "${environment}"...`)}`,
    )

    const result = await stash.list()
    if (result.failure) {
      console.error(
        style.error(`Failed to list secrets: ${result.failure.message}`),
      )
      process.exit(1)
    }

    if (result.data.length === 0) {
      console.log(
        `\n${style.warning(`No secrets found in environment "${environment}"`)}`,
      )
      return
    }

    console.log(`\n${style.title(`Secrets in environment "${environment}":`)}`)
    console.log('')

    for (const secret of result.data) {
      const name = style.value(secret.name)
      const metadata: string[] = []
      if (secret.createdAt) {
        metadata.push(
          `${style.label('created:')} ${new Date(secret.createdAt).toLocaleString()}`,
        )
      }
      if (secret.updatedAt) {
        metadata.push(
          `${style.label('updated:')} ${new Date(secret.updatedAt).toLocaleString()}`,
        )
      }

      const metaStr =
        metadata.length > 0
          ? ` ${colors.dim}(${metadata.join(', ')})${colors.reset}`
          : ''
      console.log(`  ${style.bullet()} ${name}${metaStr}`)
    }

    console.log('')
    console.log(
      style.label(
        `Total: ${result.data.length} secret${result.data.length === 1 ? '' : 's'}`,
      ),
    )
  },
  parameters: {
    flags: {
      environment: {
        kind: 'parsed',
        parse: String,
        brief: 'Environment name (e.g., production, staging, development)',
      },
    },
    aliases: {
      e: 'environment',
    },
  },
  docs: {
    brief: 'List all secrets in an environment',
    fullDescription: `
List all secrets stored in the specified environment. Only secret names and metadata
are returned; values remain encrypted and are not displayed.

Examples:
  ${cliRef} secrets list --environment production
  ${cliRef} secrets list -e production
  ${cliRef} secrets list --environment staging
		`.trim(),
  },
})

/**
 * Delete command - Delete a secret from the vault
 */
const deleteCommand = buildCommand({
  func: async (flags: { name: string; environment: string; yes?: boolean }) => {
    const { name, environment, yes } = flags
    const stash = createStash(environment)

    // Ask for confirmation unless --yes flag is set
    if (!yes) {
      const confirmation = await askConfirmation(
        `${style.warning(`Are you sure you want to delete secret "${name}" from environment "${environment}"? This action cannot be undone. (yes/no): `)}`,
      )

      if (!confirmation) {
        console.log(style.info('Deletion cancelled.'))
        return
      }
    }

    console.log(
      `${style.info(`Deleting secret "${name}" from environment "${environment}"...`)}`,
    )

    const result = await stash.delete(name)
    if (result.failure) {
      console.error(
        style.error(`Failed to delete secret: ${result.failure.message}`),
      )
      process.exit(1)
    }

    console.log(
      style.success(
        `Secret "${name}" deleted successfully from environment "${environment}"`,
      ),
    )
  },
  parameters: {
    flags: {
      name: {
        kind: 'parsed',
        parse: String,
        brief: 'Name of the secret to delete',
      },
      environment: {
        kind: 'parsed',
        parse: String,
        brief: 'Environment name (e.g., production, staging, development)',
      },
      yes: {
        kind: 'boolean',
        optional: true,
        brief: 'Skip confirmation prompt',
      },
    },
    aliases: {
      n: 'name',
      e: 'environment',
      y: 'yes',
    },
  },
  docs: {
    brief: 'Delete a secret from CipherStash',
    fullDescription: `
Permanently delete a secret from the specified environment. This action cannot be undone.
By default, you will be prompted for confirmation before deletion. Use --yes to skip the confirmation.

Examples:
  ${cliRef} secrets delete --name DATABASE_URL --environment production
  ${cliRef} secrets delete -n DATABASE_URL -e production --yes
  ${cliRef} secrets delete --name API_KEY --environment staging -y
		`.trim(),
  },
})

/**
 * Secrets route map - Groups all secret management commands
 */
const secretsRouteMap = buildRouteMap({
  routes: {
    set: setCommand,
    get: getCommand,
    list: listCommand,
    delete: deleteCommand,
  },
  docs: {
    brief: 'Manage encrypted secrets in CipherStash',
    fullDescription: `
The secrets command group provides operations for managing encrypted secrets stored in CipherStash.
All secrets are encrypted locally before being sent to the API, ensuring end-to-end encryption.

Available Commands:
  set      Store an encrypted secret
  get      Retrieve and decrypt a secret
  list     List all secrets in an environment
  delete   Delete a secret from the vault

Environment Variables:
  CS_WORKSPACE_CRN          CipherStash workspace CRN (required)
  CS_CLIENT_ID              CipherStash client ID (required)
  CS_CLIENT_KEY             CipherStash client key (required)
  CS_CLIENT_ACCESS_KEY      CipherStash client access key (required)

Examples:
  ${cliRef} secrets set --name DATABASE_URL --value "postgres://..." --environment production
  ${cliRef} secrets set -n DATABASE_URL -V "postgres://..." -e production
  ${cliRef} secrets get --name DATABASE_URL --environment production
  ${cliRef} secrets get -n DATABASE_URL -e production
  ${cliRef} secrets list --environment production
  ${cliRef} secrets list -e production
  ${cliRef} secrets delete --name DATABASE_URL --environment production
  ${cliRef} secrets delete -n DATABASE_URL -e production --yes
  ${cliRef} secrets delete -n DATABASE_URL -e production -y
		`.trim(),
  },
})

/**
 * Root command - Entry point for the CLI
 */
const rootRouteMap = buildRouteMap({
  routes: {
    secrets: secretsRouteMap,
  },
  docs: {
    brief: 'CipherStash Protect - Encrypted secrets management',
    fullDescription: `
CipherStash Protect CLI

Manage encrypted secrets with end-to-end encryption. Secrets are encrypted locally
before being sent to the CipherStash API, ensuring your plaintext never leaves
your machine unencrypted.

Quick Start:
  1. Set required environment variables (CS_WORKSPACE_CRN, CS_CLIENT_ID, etc.)
  2. Use '${cliRef} secrets set' to store your first secret
  3. Use '${cliRef} secrets get' to retrieve secrets when needed

Commands:
  secrets  Manage encrypted secrets

Run '${cliRef} <command> --help' for more information about a command.
		`.trim(),
  },
})

/**
 * Build the CLI application
 */
const app = buildApplication(rootRouteMap, {
  name: 'stash',
  versionInfo: { currentVersion: '10.2.1' },
  scanner: { caseStyle: 'allow-kebab-for-camel' },
})

/**
 * Main entry point
 */
async function main(): Promise<void> {
  try {
    await run(app, process.argv.slice(2), {
      process,
      async forCommand() {
        return {
          process,
        }
      },
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.error(style.error(`Unexpected error: ${message}`))
    process.exit(1)
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error)
  console.error(style.error(`Fatal error: ${message}`))
  process.exit(1)
})
