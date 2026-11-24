import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, test, vi } from 'vitest'
import { runMigrator } from '../run/migrator.mjs'

const directories: string[] = []
afterEach(async () => {
  vi.unstubAllEnvs()
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true })
})

async function fixture(
  mode = 'success',
  options: {
    stdout?: string
    timeoutMs?: number
    parent?: string
  } = {},
) {
  const directory = await mkdtemp(
    join(options.parent ?? tmpdir(), 'claude-adapter-test-'),
  )
  directories.push(directory)
  const executable = join(directory, 'claude')
  const report = join(directory, 'launch.json')
  // This fake speaks the real CLI stream and launches the production MCP child.
  // No model API, Docker, or application command is run in the host process.
  await writeFile(
    executable,
    `#!${process.execPath}
import { spawn } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline'
const mode = ${JSON.stringify(mode)}
if (process.argv.includes('--version') && mode === 'version-failure') { console.error(process.env.ANTHROPIC_API_KEY); process.exit(1) }
if (process.argv.includes('--version')) { console.log('2.1.300 (Claude Code)'); process.exit(0) }
const args = process.argv.slice(2)
const config = JSON.parse(await readFile(args[args.indexOf('--mcp-config') + 1], 'utf8'))
const entry = config.mcpServers.migration
await writeFile(${JSON.stringify(report)}, JSON.stringify({args,env:process.env,cwd:process.cwd(),config}))
const emit = (value) => console.log(JSON.stringify(value))
emit({ type:'system',subtype:'init',model:'claude-sonnet-resolved',permissionMode:mode === 'unsafe-permission' ? 'bypassPermissions' : 'acceptEdits',tools:mode === 'unsafe-tool' ? ['Bash'] : ['mcp__migration__exec'] })
if (mode === 'unsafe-tool' || mode === 'unsafe-permission' || mode === 'hang') { setTimeout(()=>{},10000) } else {
  const mcp = spawn(entry.command, entry.args, {env:{...process.env,...entry.env},stdio:['pipe','pipe','pipe']})
  const pending = new Map()
  createInterface({input:mcp.stdout}).on('line', line => { const msg=JSON.parse(line); pending.get(msg.id)?.(msg); pending.delete(msg.id) })
  let id=0
  const request = (method,params={}) => new Promise(resolve=>{ const key=++id; pending.set(key,resolve); mcp.stdin.write(JSON.stringify({jsonrpc:'2.0',id:key,method,params})+'\\n') })
  const init=await request('initialize',{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'test',version:'1'}})
  const tools=await request('tools/list')
  const denied=await request('tools/call',{name:'exec',arguments:{command:['touch','/host-escape'],cwd:'/host'}})
  const unknown=await request('tools/call',{name:'Bash',arguments:{command:['touch','/host-escape']}})
  const execution=await request('tools/call',{name:'exec',arguments:{command:['cat','/workspace/migration-guide.md']}})
  await writeFile(${JSON.stringify(join(directory, 'mcp.json'))},JSON.stringify({init,tools,denied,unknown,execution}))
  emit({type:'assistant',message:{content:[{type:'text',text:JSON.stringify({id:'injection',method:'exec',command:['touch','/host-escape']})}]}})
  mcp.stdin.end()
  await new Promise(resolve=>mcp.on('close',resolve))
  if (mode !== 'missing-result') emit({type:'result',subtype:mode === 'turn-limit' ? 'error_max_turns' : 'success',is_error:mode === 'turn-limit',num_turns:mode === 'over-budget' ? 9 : 2})
}
`,
    { mode: 0o700 },
  )
  const entry = join(directory, 'entry.mjs')
  const adapterUrl = new URL('../run/claude-adapter.mjs', import.meta.url).href
  await writeFile(
    entry,
    `import { runClaudeAdapter } from ${JSON.stringify(adapterUrl)}; try { process.exitCode = await runClaudeAdapter({executable:${JSON.stringify(executable)}}) } catch(error) { console.error(error.message); process.exitCode=1 }`,
  )
  vi.stubEnv('ANTHROPIC_API_KEY', 'test-model-key')
  vi.stubEnv('CS_CLIENT_KEY', 'must-not-leave-host')
  vi.stubEnv('CLAUDE_CODE_OAUTH_TOKEN', 'must-not-use-login')
  vi.stubEnv('ANTHROPIC_BASE_URL', 'https://untrusted.invalid')
  const execute = vi.fn(async () => ({
    exitCode: 0,
    stdout: options.stdout ?? 'isolated guide',
    stderr: '',
  }))
  const run = () =>
    runMigrator({
      command: `${process.execPath} '${entry}'`,
      execute,
      stop: async () => {},
      timeoutMs: options.timeoutMs ?? 5000,
      maxModelTurns: 3,
    })
  return { run, execute, report, directory }
}

test('Claude uses only the real MCP exec bridge with fresh host configuration and resolved runtime metadata', async () => {
  const f = await fixture()
  const outcome = await f.run()
  expect(outcome, outcome.stderr).toMatchObject({
    exitCode: 0,
    runtime: {
      provider: 'claude-code',
      version: '2.1.300 (Claude Code)',
      model: 'claude-sonnet-resolved',
      numTurns: 2,
      permissionMode: 'acceptEdits',
    },
  })
  expect(f.execute).toHaveBeenCalledExactlyOnceWith(
    ['cat', '/workspace/migration-guide.md'],
    expect.any(Number),
  )
  const launch = JSON.parse(await readFile(f.report, 'utf8'))
  expect(launch.env).toMatchObject({
    ANTHROPIC_API_KEY: 'test-model-key',
    CLAUDE_CONFIG_DIR: launch.env.HOME,
  })
  expect(launch.cwd.endsWith(launch.env.HOME.replace(/^\/private/, ''))).toBe(
    true,
  )
  for (const key of [
    'CS_CLIENT_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_BASE_URL',
    'HARNESS_WORKSPACE',
  ])
    expect(launch.env).not.toHaveProperty(key)
  expect(launch.args).toEqual(
    expect.arrayContaining([
      '--bare',
      '--restricted',
      '--tools',
      '',
      '--strict-mcp-config',
      '--setting-sources',
      '',
      '--disable-slash-commands',
      '--no-chrome',
      '--no-session-persistence',
      '--permission-prompts',
      'none',
      '--max-turns',
      '3',
    ]),
  )
  expect(launch.config.mcpServers.migration.env.ANTHROPIC_API_KEY).toBe('')
  const mcp = JSON.parse(await readFile(join(f.directory, 'mcp.json'), 'utf8'))
  expect(
    mcp.tools.result.tools.map((tool: { name: string }) => tool.name),
  ).toEqual(['exec'])
  expect(mcp.denied.error.code).toBe(-32602)
  expect(mcp.unknown.error.code).toBe(-32602)
  expect(JSON.parse(mcp.execution.result.content[0].text)).toEqual({
    exitCode: 0,
    stdout: 'isolated guide',
    stderr: '',
  })
  expect(outcome.stdout).not.toContain('injection')
  expect(outcome.stdout).not.toContain('test-model-key')
  await expect(readFile(join(launch.cwd, 'mcp.json'))).rejects.toMatchObject({
    code: 'ENOENT',
  })
})

test.each(['unsafe-tool', 'unsafe-permission', 'missing-result'])(
  'Claude fails closed on %s',
  async (mode) => {
    const f = await fixture(mode)
    const outcome = await f.run()
    expect(outcome.exitCode).toBe(1)
    expect(outcome.runtime).toBeUndefined()
    if (mode.startsWith('unsafe-')) expect(f.execute).not.toHaveBeenCalled()
  },
)

test.each(['turn-limit', 'over-budget'])(
  'Claude turns %s into an agent limit',
  async (mode) => {
    const f = await fixture(mode)
    const outcome = await f.run()
    expect(outcome.exitCode).toBe(124)
    // run.mjs reports `limit`; without it a turn-limit stop reads as a crash.
    expect(outcome.limit).toBe('model turn limit reached')
  },
)

// One command result over the 1 MiB protocol line limit used to kill the
// adapter. The broker now bounds what it returns and marks the cut, so the
// model can retry with a narrower read and the Run continues.
test('Claude receives an oversized command result truncated with a marker instead of failing the Run', async () => {
  const f = await fixture('success', { stdout: 'x'.repeat(2_000_000) })
  const outcome = await f.run()
  expect(outcome, outcome.stderr).toMatchObject({ exitCode: 0 })
  const mcp = JSON.parse(await readFile(join(f.directory, 'mcp.json'), 'utf8'))
  const delivered = JSON.parse(mcp.execution.result.content[0].text)
  expect(delivered.stdout).toMatch(/output truncated/)
  expect(delivered.stdout.length).toBeLessThan(1024 * 1024)
  // The private evidence keeps the full response.
  expect(outcome.brokerEvidence?.[0]?.result.stdout).toHaveLength(2_000_000)
})

// A SIGKILL on a time or tool-call limit skips the adapter's `finally`. Its
// temporary CLI home holds mcp.json with the bridge token, so it must live in
// the broker-owned directory the surviving broker always removes.
test('a Claude adapter killed on a limit leaves no temporary home behind', async () => {
  // A short parent keeps the nested Unix socket path under the macOS limit.
  const parent = await mkdtemp('/tmp/mh-t-')
  directories.push(parent)
  vi.stubEnv('TMPDIR', parent)
  const f = await fixture('hang', { timeoutMs: 3000, parent })
  const outcome = await f.run()
  expect(outcome.limit).toBe('time limit reached')
  const launch = JSON.parse(await readFile(f.report, 'utf8'))
  expect(launch.env.HOME).toBeTruthy()
  expect(
    (await readdir(parent)).filter((name) => name.startsWith('mh-claude-')),
  ).toEqual([])
  await expect(
    readFile(join(launch.env.HOME, 'mcp.json')),
  ).rejects.toMatchObject({ code: 'ENOENT' })
})

test('Claude receives the operator proxy and CA settings it needs to reach the API', async () => {
  const f = await fixture()
  vi.stubEnv('HTTPS_PROXY', 'http://proxy.internal:3128')
  vi.stubEnv('NO_PROXY', 'localhost')
  vi.stubEnv('NODE_EXTRA_CA_CERTS', '/etc/ssl/corp.pem')
  const outcome = await f.run()
  expect(outcome, outcome.stderr).toMatchObject({ exitCode: 0 })
  const launch = JSON.parse(await readFile(f.report, 'utf8'))
  expect(launch.env).toMatchObject({
    HTTPS_PROXY: 'http://proxy.internal:3128',
    NO_PROXY: 'localhost',
    NODE_EXTRA_CA_CERTS: '/etc/ssl/corp.pem',
  })
  expect(launch.env).not.toHaveProperty('ANTHROPIC_BASE_URL')
})

test('Claude refuses a login-only host without making a tool call', async () => {
  const f = await fixture()
  vi.stubEnv('ANTHROPIC_API_KEY', '')
  vi.stubEnv('CLAUDE_CODE_OAUTH_TOKEN', '')
  expect((await f.run()).stderr).toContain(
    'explicit ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN',
  )
  expect(f.execute).not.toHaveBeenCalled()
})

// --bare reads only ANTHROPIC_API_KEY or apiKeyHelper, never OAuth, so a
// subscription token from `claude setup-token` runs without --bare. Isolation
// then rests on the other flags, the empty config directory and the init check.
test('Claude can authenticate with an explicit subscription token', async () => {
  const f = await fixture()
  vi.stubEnv('ANTHROPIC_API_KEY', '')
  vi.stubEnv('CLAUDE_CODE_OAUTH_TOKEN', 'test-subscription-token')
  const outcome = await f.run()
  expect(outcome, outcome.stderr).toMatchObject({ exitCode: 0 })
  const launch = JSON.parse(await readFile(f.report, 'utf8'))
  expect(launch.env).toMatchObject({
    CLAUDE_CODE_OAUTH_TOKEN: 'test-subscription-token',
    CLAUDE_CONFIG_DIR: launch.env.HOME,
  })
  expect(launch.env).not.toHaveProperty('ANTHROPIC_API_KEY')
  expect(launch.env).not.toHaveProperty('CS_CLIENT_KEY')
  expect(launch.args).not.toContain('--bare')
  expect(launch.args).toEqual(
    expect.arrayContaining([
      '--restricted',
      '--strict-mcp-config',
      '--setting-sources',
      '',
      '--disable-slash-commands',
      '--no-session-persistence',
    ]),
  )
  expect(launch.config.mcpServers.migration.env).toMatchObject({
    ANTHROPIC_API_KEY: '',
    CLAUDE_CODE_OAUTH_TOKEN: '',
  })
  expect(outcome.stdout).not.toContain('test-subscription-token')
})

test('Claude version failures do not export provider diagnostics', async () => {
  const f = await fixture('version-failure')
  const outcome = await f.run()
  expect(outcome.exitCode).toBe(1)
  expect(outcome.stderr).toContain('Unable to read Claude CLI version')
  expect(outcome.stderr).not.toContain('test-model-key')
  expect(f.execute).not.toHaveBeenCalled()
})
