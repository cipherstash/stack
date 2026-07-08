import { messages } from '../../messages.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'
import { bindDevice, login } from './login.js'
import { failRegion, regionList, resolveRegion } from './region.js'

const STASH_AUTH = runnerCommand(detectPackageManager(), 'stash auth')

const HELP = `
${messages.auth.usagePrefix}${STASH_AUTH} <command> [options]

Commands:
  login     Authenticate with CipherStash
  regions   List the regions you can authenticate against

Options:
  --region <slug>   Region to authenticate against (e.g. us-east-1). Skips the
                    interactive picker. Also settable via STASH_REGION.
  --json            Emit newline-delimited JSON events instead of prose. The
                    first event (authorization_required) carries the device
                    verification URL for a human to open; implies no prompt and
                    no browser auto-open.
  --no-open         Don't auto-open the verification URL in a browser.
  --supabase        Track Supabase as the referrer
  --drizzle         Track Drizzle as the referrer

Examples:
  ${STASH_AUTH} login
  ${STASH_AUTH} login --region us-east-1
  ${STASH_AUTH} login --supabase
  ${STASH_AUTH} regions            # list available regions
  ${STASH_AUTH} regions --json     # machine-readable [{slug,label}]
  # Agent triggers auth; a human completes it in the browser:
  ${STASH_AUTH} login --region us-east-1 --json
`.trim()

function referrerFromFlags(flags: Record<string, boolean>): string | undefined {
  const parts: string[] = []
  if (flags.drizzle) parts.push('drizzle')
  if (flags.supabase) parts.push('supabase')
  return parts.length > 0 ? parts.join('-') : undefined
}

/**
 * `stash auth regions` — enumerate the regions valid for `--region` /
 * `STASH_REGION`. Plain stdout (no clack chrome) so it pipes cleanly;
 * `--json` emits the structured `[{ slug, label }]` an agent can consume.
 */
function printRegions(json: boolean): void {
  const list = regionList()
  if (json) {
    console.log(JSON.stringify(list))
    return
  }
  console.log('Available regions (pass one to --region or set STASH_REGION):\n')
  for (const r of list) {
    console.log(`  ${r.label}`)
  }
}

export async function authCommand(
  args: string[],
  flags: Record<string, boolean>,
  values: Record<string, string> = {},
) {
  const subcommand = args[0]

  if (!subcommand || subcommand === '--help' || subcommand === '-h') {
    console.log(HELP)
    return
  }

  const referrer = referrerFromFlags(flags)
  const json = flags.json ?? false

  switch (subcommand) {
    case 'login':
      {
        // `--region` with no value: parseArgs booleanises a valueless flag, so
        // it lands in `flags`, not `values`. Fail with a precise message rather
        // than silently falling through to the generic "region required".
        if (flags.region) {
          failRegion(json, 'region_invalid', messages.auth.regionFlagNeedsValue)
        }
        const region = await resolveRegion({ regionFlag: values.region, json })
        await login(region, referrer, {
          json,
          open: !json && !flags['no-open'],
        })
        await bindDevice({ json })
      }
      break
    case 'regions':
      printRegions(json)
      break
    default:
      console.error(`${messages.auth.unknownSubcommand}: ${subcommand}\n`)
      console.log(HELP)
      process.exit(1)
  }
}
