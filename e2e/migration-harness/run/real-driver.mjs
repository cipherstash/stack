import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { cp, mkdir, open, readFile, rm, writeFile } from 'node:fs/promises'
import { relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'
import { behaviour, legacy, mutation } from './behaviour.mjs'
import { noRewrite, validateLegacySnapshot } from './no-rewrite.mjs'
import { createStoreSet, disposeStores } from './real-stores.mjs'
import { prepareWorkspace } from './workspace.mjs'

/** @typedef {Awaited<ReturnType<typeof createStoreSet>>} StoreSet
 * @typedef {Pick<ReturnType<typeof import('../isolation.mjs').createIsolation>, 'prove'|'exec'|'openAppHost'|'stop'>} Isolation */
/** Real application execution has exactly one route: the proven isolation host.
 * @param {{id:string,root:string,output:string,command:string,isolation:Isolation,credentials:Record<string,string>,manifest:import('../types.js').Manifest & {stack:string}}} options */
export function createRealDriver({
  id,
  root,
  output,
  command,
  isolation,
  credentials,
  manifest,
}) {
  /** @type {import('./real-stores.mjs').Resource[]} */
  const resources = []
  const workspace = resolve(output, 'migrator')
  const oracleWorkspace = resolve(output, 'app-host')
  /** @type {StoreSet|null} */
  let migratorStores = null
  /** @type {StoreSet|null} */
  let oracleStores = null
  /** @type {Awaited<ReturnType<Isolation['openAppHost']>>|null} */
  let host = null
  /** @type {unknown} */
  let legacySnapshot
  /** @param {StoreSet|null} stores */
  function assigned(stores) {
    if (!stores) throw Error('Run Store Set has not been provisioned')
    return stores
  }
  const serviceNames = new Set(['registry.npmjs.org'])
  for (const key of ['CS_CTS_HOST', 'CS_ZEROKMS_HOST'])
    if (credentials[key]) serviceNames.add(new URL(credentials[key]).hostname)
  const region = credentials.CS_WORKSPACE_CRN?.split(':')[1]
  if (region) {
    serviceNames.add(`${region}.cts.cipherstashmanaged.net`)
    serviceNames.add(`${region}.viturhosted.net`)
  }
  const services = [...serviceNames].map((host) => ({
    host,
    port: 443,
    targetHost: host,
    targetPort: 443,
  }))
  /** @param {StoreSet|null} stores */
  function env(stores) {
    return {
      ...credentials,
      ...assigned(stores).env,
      HARNESS_GUIDE: '/workspace/migration-guide.md',
      HARNESS_WORKSPACE: '/workspace',
      HARNESS_FRICTION_LOG: '/workspace/friction.json',
      HARNESS_STACK_VERSION: manifest.stack,
    }
  }
  /** @param {StoreSet|null} stores */
  function forwards(stores) {
    return [...assigned(stores).forwards, ...services]
  }
  /** @param {string} actor @param {string} directory @param {StoreSet|null} stores @param {string[]} argv */
  async function execute(actor, directory, stores, argv) {
    const result = await isolation.exec({
      actor,
      workspace: directory,
      env: env(stores),
      command: argv,
      forwards: forwards(stores),
    })
    await writeFile(
      resolve(output, `${actor}-${Date.now()}.log`),
      `${result.stdout ?? ''}\n${result.stderr ?? ''}`,
    )
    if (result.exitCode !== 0)
      throw Error(`${actor} command exited ${result.exitCode}`)
    return result
  }
  return {
    async provision() {
      await mkdir(output, { recursive: true })
      const proof = await isolation.prove()
      if (proof?.verified !== true)
        throw Error('Isolation capability proof failed')
      manifest.isolation = proof
      const resolved = JSON.parse(
        (
          await promisify(execFile)('npm', [
            'view',
            `@cipherstash/stack@${manifest.stack}`,
            'version',
            '--json',
          ])
        ).stdout,
      )
      manifest.stack = Array.isArray(resolved) ? resolved.at(-1) : resolved
      if (
        typeof manifest.stack !== 'string' ||
        !/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(manifest.stack)
      )
        throw Error('Could not resolve exact Stack version')
      const guide = resolve(root, 'docs/migration/protect-dynamodb-to-stack.md')
      const content = await readFile(guide, 'utf8')
      manifest.guideHash = createHash('sha256').update(content).digest('hex')
      const counts = new Map()
      manifest.guideSections = [
        'preamble',
        ...content
          .split('\n')
          .filter((line) => /^#{1,6}\s/.test(line))
          .map((line) => {
            const slug = line
              .replace(/^#{1,6}\s+/, '')
              .toLowerCase()
              .replace(/[^a-z0-9]+/g, '-')
              .replace(/^-|-$/g, '')
            const n = (counts.get(slug) ?? 0) + 1
            counts.set(slug, n)
            return n === 1 ? slug : `${slug}-${n}`
          }),
      ]
      await prepareWorkspace({
        fixture: resolve(root, 'e2e/migration-harness/fixture'),
        workspace,
        guide,
        frictionPath: '/workspace/friction.json',
      })
      const eqlBundle = resolve(
        root,
        'packages/eql/packages/eql/sql/cipherstash-encrypt.sql',
      )
      migratorStores = await createStoreSet({
        runId: id,
        actor: 'migrator',
        eqlBundle,
        resources,
      })
      oracleStores = await createStoreSet({
        runId: id,
        actor: 'oracle',
        eqlBundle,
        resources,
      })
      manifest.storeCapabilities = {
        migrator: await migratorStores.verify(),
        oracle: await oracleStores.verify(),
      }
    },
    async installUnmigrated() {
      await execute('migrator', workspace, migratorStores, ['npm', 'install'])
      await cp(workspace, oracleWorkspace, { recursive: true })
    },
    async initializeLegacyData() {
      /** @type {[string,string,StoreSet|null][]} */
      const targets = [
        ['migrator', workspace, migratorStores],
        ['app-host', oracleWorkspace, oracleStores],
      ]
      for (const [actor, directory, stores] of targets) {
        const initializationHost = await isolation.openAppHost({
          actor,
          workspace: directory,
          env: env(stores),
          forwards: forwards(stores),
        })
        try {
          for (const record of [legacy, mutation]) {
            await initializationHost.call('put', [record])
            await initializationHost.call('copyToPostgres', [record.pk])
          }
        } finally {
          await initializationHost.close()
        }
      }
    },
    async snapshot() {
      legacySnapshot = await assigned(oracleStores).snapshot()
      validateLegacySnapshot(legacySnapshot)
      await writeFile(
        resolve(output, 'legacy-snapshot.json'),
        JSON.stringify(legacySnapshot),
      )
    },
    async migrate() {
      const result = await isolation.exec({
        actor: 'migrator',
        workspace,
        env: env(migratorStores),
        command: ['/bin/sh', '-lc', command],
        forwards: forwards(migratorStores),
        timeoutMs: manifest.agents?.limits?.timeMs,
      })
      await writeFile(
        resolve(output, 'migrator-transcript.log'),
        `${result.stdout ?? ''}\n${result.stderr ?? ''}`,
      )
      await isolation.exec({
        actor: 'migrator',
        workspace,
        env: env(migratorStores),
        command: [
          'git',
          'add',
          '-N',
          '--',
          '.',
          ':(exclude)node_modules',
          ':(exclude)**/node_modules/**',
        ],
        forwards: forwards(migratorStores),
        timeoutMs: manifest.agents?.limits?.timeMs,
      })
      const diff = await isolation.exec({
        actor: 'migrator',
        workspace,
        env: env(migratorStores),
        command: [
          'git',
          '-c',
          'core.pager=cat',
          'diff',
          '--no-ext-diff',
          '--no-textconv',
          'HEAD',
        ],
        forwards: forwards(migratorStores),
        timeoutMs: manifest.agents?.limits?.timeMs,
      })
      await writeFile(resolve(output, 'migration.diff'), diff.stdout)
      manifest.artifacts = {
        transcript: 'migrator-transcript.log',
        diff: 'migration.diff',
        snapshot: 'legacy-snapshot.json',
      }
      return result
    },
    async friction() {
      const file = await open(
        resolve(workspace, 'friction.json'),
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      )
      try {
        const stat = await file.stat()
        if (!stat.isFile() || stat.nlink !== 1 || stat.size > 1024 * 1024)
          throw Error('Invalid Friction Log file')
        try {
          return JSON.parse(await file.readFile('utf8'))
        } catch {
          throw Error('Malformed Friction Log JSON')
        }
      } finally {
        await file.close()
      }
    },
    async installAppHost() {
      await rm(oracleWorkspace, { recursive: true, force: true })
      await cp(workspace, oracleWorkspace, {
        recursive: true,
        force: true,
        filter: (source) =>
          !relative(workspace, source)
            .split(sep)
            .some((part) => ['node_modules', '.git'].includes(part)),
      })
      await execute('app-host', oracleWorkspace, oracleStores, [
        'npm',
        'install',
        '--save-exact',
        `@cipherstash/stack@${manifest.stack}`,
      ])
      host = await isolation.openAppHost({
        actor: 'app-host',
        workspace: oracleWorkspace,
        env: env(oracleStores),
        forwards: forwards(oracleStores),
      })
    },
    async behaviour() {
      const application = host
      if (!application) throw Error('App Host has not started')
      try {
        const result = await behaviour((method, args) =>
          application.call(method, args),
        )
        let current
        try {
          current = await assigned(oracleStores).snapshot()
        } catch (error) {
          throw Object.assign(
            new Error('Oracle snapshot read failed', { cause: error }),
            { infrastructure: true },
          )
        }
        result.checks.push(noRewrite(legacySnapshot, current))
        return await result.mutate()
      } finally {
        await application.close()
        host = null
      }
    },
    async close() {
      if (host) await host.close().catch(() => {})
      await isolation.stop()
      await disposeStores(resources)
    },
  }
}
