import { readFileSync } from 'node:fs'
import { relative, resolve } from 'node:path'
import yaml from 'js-yaml'

const REPO_ROOT = resolve(import.meta.dirname, '..')

// Default targets — the workflows the supply-chain gate covers. Override with
// argv[2..] for tests / ad-hoc multi-file checks.
const TARGETS = process.argv.slice(2).length
  ? process.argv.slice(2)
  : ['.github/workflows/release.yml', '.github/workflows/tests-supply-chain.yml']

// `uses:` values that pull in the GitHub Actions cache directly.
const CACHE_ACTION = /^actions\/cache(\/(restore|save))?@/

// Steps that must disable their built-in caching *explicitly* — leaving the
// key off and relying on the default is not enough: the gate asserts intent.
const PNPM_ACTION_SETUP = /^pnpm\/action-setup(@|$)/
const SETUP_NODE = /^actions\/setup-node(@|$)/

function stepLabel(step, idx) {
  return step?.name || step?.uses || `step #${idx + 1}`
}

// Returns a reason string if `inputName` is not explicitly set to boolean
// `false` on the step's `with:`, otherwise null.
function explicitFalseReason(step, inputName) {
  const w = step?.with
  if (!w || !Object.hasOwn(w, inputName)) {
    return `must set \`${inputName}: false\` explicitly (key missing)`
  }
  if (w[inputName] !== false) {
    return `\`${inputName}\` must be \`false\`, found ${JSON.stringify(w[inputName])}`
  }
  return null
}

const offenders = []
for (const target of TARGETS) {
  const abs = resolve(REPO_ROOT, target)
  const rel = relative(REPO_ROOT, abs)
  const doc = yaml.load(readFileSync(abs, 'utf8'))
  const jobs = doc?.jobs ?? {}
  for (const [jobName, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job?.steps) ? job.steps : []
    steps.forEach((step, idx) => {
      const label = stepLabel(step, idx)
      const at = `${rel}: job "${jobName}" step "${label}"`

      // `cache:` under a step's `with:` — covers actions/setup-node,
      // actions/setup-python, etc. An explicit falsy value does not count.
      if (step?.with && Object.hasOwn(step.with, 'cache') && step.with.cache) {
        offenders.push(
          `${at}: \`with.cache: ${JSON.stringify(step.with.cache)}\` restores the GitHub Actions cache`,
        )
      }

      // `uses: actions/cache...`
      if (typeof step?.uses === 'string' && CACHE_ACTION.test(step.uses)) {
        offenders.push(`${at}: uses \`${step.uses}\` (GitHub Actions cache)`)
      }

      // Explicit-disable assertions for the package-manager setup actions.
      if (typeof step?.uses === 'string') {
        if (PNPM_ACTION_SETUP.test(step.uses)) {
          const reason = explicitFalseReason(step, 'cache')
          if (reason) offenders.push(`${at}: pnpm/action-setup ${reason}`)
        }
        if (SETUP_NODE.test(step.uses)) {
          const reason = explicitFalseReason(step, 'package-manager-cache')
          if (reason) offenders.push(`${at}: actions/setup-node ${reason}`)
        }
      }
    })
  }
}

if (offenders.length > 0) {
  console.error(`Found ${offenders.length} caching issue(s) in workflow(s):\n`)
  for (const o of offenders) console.error(`  ${o}`)
  console.error(
    '\nThese workflows must not restore the GitHub Actions cache — it is a\n' +
      'cache-poisoning / supply-chain vector for credential-bearing jobs.\n' +
      'Caching must be disabled explicitly (`cache: false`,\n' +
      '`package-manager-cache: false`). See the "CI/CD Supply-Chain\n' +
      'Hardening" section of SECURITY.md.',
  )
  process.exit(1)
}

console.log('OK — GitHub Actions caching is explicitly disabled in:\n')
for (const target of TARGETS) console.log(target)
