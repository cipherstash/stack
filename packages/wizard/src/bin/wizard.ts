import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as p from '@clack/prompts'
import { config } from 'dotenv'
import { detectPackageManager } from '../lib/detect.js'
import { run } from '../run.js'
import { parseArgs } from './parse-args.js'

/**
 * Load env files in Next.js precedence order. dotenv's default behaviour
 * is to not overwrite vars already set, so loading `.env.local` first
 * means its values win over `.env` for the same keys. Users can still
 * set anything in the real environment to override both.
 */
function loadDotenv(): void {
  config({ path: '.env.local' })
  config({ path: '.env.development.local' })
  config({ path: '.env.development' })
  config({ path: '.env' })
}

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(
  readFileSync(join(__dirname, '../../package.json'), 'utf-8'),
)

const RUNNER = detectPackageManager(process.cwd())?.execCommand ?? 'npx'

const HELP = `
CipherStash Wizard v${pkg.version}

Usage: ${RUNNER} @cipherstash/wizard [options]

The wizard reads your codebase and wires up @cipherstash/stack encryption
for the columns you select. Run it once per project, after \`stash init\`.

Options:
  --help, -h           Show help
  --version, -v        Show version
  --debug              Print extra diagnostics from the agent
  --plan               Drafts \`.cipherstash/plan.md\` for review.
                       No code or schema changes, no db pushes.
  --implement          Full setup flow (the default).
  --mode <plan|implement>
                       Long form of \`--plan\` / \`--implement\`. Last mode
                       flag wins if multiple are passed.
`.trim()

async function main() {
  const { help, version, debug, mode, modeError } = parseArgs(process.argv)

  if (help) {
    console.log(HELP)
    return
  }

  if (version) {
    console.log(pkg.version)
    return
  }

  if (modeError) {
    p.log.error(modeError)
    process.exit(1)
  }

  // Defer env loading until we're actually running — `--help` / `--version`
  // shouldn't pay for it, and a malformed `--mode` should exit before it
  // touches disk.
  loadDotenv()

  await run({
    cwd: process.cwd(),
    debug,
    cliVersion: pkg.version,
    mode,
  })
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err)
  p.log.error(`Fatal error: ${message}`)
  process.exit(1)
})
