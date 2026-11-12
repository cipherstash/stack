import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { cp, mkdir, open, readFile, rm, writeFile } from 'node:fs/promises'
import { relative, resolve, sep } from 'node:path'
import { isDeepStrictEqual, promisify } from 'node:util'
import { behaviour, legacy, mutation } from './behaviour.mjs'
import { fakeMigrate } from './fake-migrator.mjs'
import { migrationChecks } from './migration-checks.mjs'
import { runMigrator } from './migrator.mjs'
import { noRewrite, validateLegacySnapshot } from './no-rewrite.mjs'
import { postgresBehaviour, postgresLegacy } from './postgres-behaviour.mjs'
import {
  postgresFreshWriteCheck,
  postgresMigrationChecks,
  validatePostgresBaseline,
} from './postgres-oracle.mjs'
import { createStoreSet, disposeStores } from './real-stores.mjs'
import { isSnapshotInfrastructureError } from './snapshot-errors.mjs'
import { resolveStack } from './stack-source.mjs'
import { prepareWorkspace } from './workspace.mjs'

/** @typedef {Awaited<ReturnType<typeof createStoreSet>>} StoreSet
 * @typedef {Pick<ReturnType<typeof import('../isolation.mjs').createIsolation>, 'prove'|'exec'|'openAppHost'|'stop'>} Isolation */
/** Real application execution has exactly one route: the proven isolation host.
 * @param {{id:string,root:string,output:string,command:string,fakeMigration?:string,isolation:Isolation,credentials:Record<string,string>,manifest:import('../types.js').Manifest & {stack:string}}} options */
export function createRealDriver({
  id,
  root,
  output,
  command,
  fakeMigration,
  isolation,
  credentials,
  manifest,
}) {
  const procedure = manifest.procedure ?? 'dynamodb'
  if (!['dynamodb', 'postgres-v2-to-v3'].includes(procedure))
    throw Error('Unknown migration procedure')
  const postgresUpgrade = procedure === 'postgres-v2-to-v3'
  manifest.procedure = procedure
  manifest.sourceEqlGeneration = 2
  manifest.targetEqlGeneration = 3
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
  let baseCommit = ''
  let ffiRange = ''
  /** @type {Awaited<ReturnType<typeof resolveStack>>|undefined} */
  let stackSource
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
  /** Runs one isolated command and keeps its output, whatever its exit code.
   * @param {string} actor @param {string} directory @param {StoreSet|null} stores @param {string[]} argv */
  async function attempt(actor, directory, stores, argv) {
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
    return result
  }
  /** @param {string} actor @param {string} directory @param {StoreSet|null} stores @param {string[]} argv */
  async function execute(actor, directory, stores, argv) {
    const result = await attempt(actor, directory, stores, argv)
    if (result.exitCode !== 0)
      throw Error(`${actor} command exited ${result.exitCode}`)
    return result
  }
  /** Reads the Oracle database with the harness's admin connection. A store
   * transport failure is infrastructure; anything else is migration damage. */
  async function oracleSnapshot() {
    try {
      return await assigned(oracleStores).postgresSnapshot()
    } catch (error) {
      throw Object.assign(
        Error('PostgreSQL Oracle snapshot failed', { cause: error }),
        { infrastructure: isSnapshotInfrastructureError(error) },
      )
    }
  }
  /** The guide runs the PostgreSQL conversion as a one-off step in a
   * write-maintenance window, not at application startup. The Oracle runs the
   * workspace's `src/migrate.mjs` `migrate(env)` inside App Host against its
   * fresh database, then runs it again: a rerun must either succeed without
   * changing data or refuse without changing anything. Data, not the exit
   * code, decides the rerun check.
   * @returns {Promise<import('../types.js').OracleCheck[]>} */
  async function postgresConversion() {
    const convert = () =>
      attempt('app-host', oracleWorkspace, oracleStores, [
        'node',
        '/harness/app-host.mjs',
        'migrate',
      ])
    const first = await convert()
    if (first.exitCode !== 0)
      return [
        {
          id: 'migration.postgres-migrate',
          passed: false,
          cause: `migrate(env) exited ${first.exitCode}`,
        },
        {
          id: 'migration.postgres-migrate-rerun',
          passed: false,
          cause: 'Rerun not checked: the first migrate(env) failed',
        },
      ]
    const before = await oracleSnapshot()
    const rerun = await convert()
    const after = await oracleSnapshot()
    const unchanged = isDeepStrictEqual(before, after)
    return [
      { id: 'migration.postgres-migrate', passed: true },
      {
        id: 'migration.postgres-migrate-rerun',
        passed: unchanged,
        ...(unchanged
          ? {}
          : {
              cause: `Rerunning migrate(env) changed stored data (exit ${rerun.exitCode})`,
            }),
      },
    ]
  }
  return {
    async provision() {
      await mkdir(output, { recursive: true })
      const proof = await isolation.prove()
      if (proof?.verified !== true)
        throw Error('Isolation capability proof failed')
      manifest.isolation = proof
      stackSource = await resolveStack({ source: manifest.stack, root, output })
      manifest.stack = stackSource.version
      manifest.stackSource = stackSource
      ffiRange = stackSource.ffiRange
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
        fixture: resolve(
          root,
          `e2e/migration-harness/${postgresUpgrade ? 'postgres-fixture' : 'fixture'}`,
        ),
        workspace,
        guide,
        frictionPath: '/workspace/friction.json',
        guideSections: manifest.guideSections,
      })
      baseCommit = (
        await promisify(execFile)('git', ['rev-parse', 'HEAD'], {
          cwd: workspace,
        })
      ).stdout.trim()
      const eqlBundle = resolve(
        root,
        'packages/eql/packages/eql/sql/cipherstash-encrypt.sql',
      )
      migratorStores = await createStoreSet({
        runId: id,
        actor: 'migrator',
        eqlBundle,
        postgresV2: postgresUpgrade,
        resources,
      })
      oracleStores = await createStoreSet({
        runId: id,
        actor: 'oracle',
        eqlBundle,
        postgresV2: postgresUpgrade,
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
          for (const record of postgresUpgrade
            ? postgresLegacy
            : [legacy, mutation]) {
            await initializationHost.call('put', [record])
            if (!postgresUpgrade)
              await initializationHost.call('copyToPostgres', [record.pk])
          }
          if (postgresUpgrade) {
            const result = await postgresBehaviour((method, args) =>
              initializationHost.call(method, args),
            )
            if (result.checks.some((check) => !check.passed))
              throw Error(
                'Legacy PostgreSQL reads or queries failed before migration',
              )
          }
        } finally {
          await initializationHost.close()
        }
      }
    },
    async snapshot() {
      legacySnapshot = postgresUpgrade
        ? await assigned(oracleStores).postgresSnapshot()
        : await assigned(oracleStores).snapshot()
      if (postgresUpgrade) validatePostgresBaseline(legacySnapshot)
      else validateLegacySnapshot(legacySnapshot)
      await writeFile(
        resolve(output, 'legacy-snapshot.json'),
        JSON.stringify(legacySnapshot),
      )
    },
    async migrate() {
      manifest.documentationExposure = {
        status: 'unknown',
        reviewRequired: true,
        evidenceComplete: false,
      }
      if (!stackSource) throw Error('Stack source not resolved')
      if (stackSource.tarball)
        await cp(stackSource.tarball, resolve(workspace, 'resolved-stack.tgz'))
      const result = fakeMigration
        ? await fakeMigrate({
            root,
            workspace,
            kind: fakeMigration,
            stack: stackSource.install,
            procedure,
          })
        : await runMigrator({
            command,
            timeoutMs: manifest.agents?.limits?.timeMs,
            maxToolCalls: manifest.agents?.limits?.toolCalls,
            maxModelTurns: manifest.agents?.limits?.turns,
            stop: () => isolation.stop({ expected: true }),
            execute: (argv, timeoutMs) =>
              isolation.exec({
                actor: 'migrator',
                workspace,
                env: env(migratorStores),
                command: argv,
                forwards: forwards(migratorStores),
                timeoutMs,
              }),
          })
      if ('brokerEvidence' in result && result.brokerEvidence) {
        await writeFile(
          resolve(output, 'broker-evidence.json'),
          JSON.stringify({
            complete: result.documentationExposure?.evidenceComplete ?? false,
            records: result.brokerEvidence,
          }),
          { mode: 0o600, flag: 'wx' },
        )
        manifest.documentationExposure = result.documentationExposure
      }
      if ('runtime' in result && result.runtime)
        manifest.agents = { ...manifest.agents, runtime: result.runtime }
      if (fakeMigration && fakeMigration !== 'noop')
        await execute('migrator', workspace, migratorStores, ['npm', 'install'])
      await writeFile(
        resolve(output, 'migrator-transcript.log'),
        `${result.stdout ?? ''}\n${result.stderr ?? ''}`,
      )
      manifest.artifacts = {
        transcript: 'migrator-transcript.log',
        ...('brokerEvidence' in result
          ? { brokerEvidence: 'broker-evidence.json' }
          : {}),
        snapshot: 'legacy-snapshot.json',
      }
      // A timed-out broker has stopped its isolated tools and proof relays.
      // Preserve its agent-limit result rather than restarting work for a diff.
      if (result.exitCode !== 0 || result.limit) return result
      const intent = await isolation.exec({
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
      if (intent.exitCode !== 0)
        throw Error(`git add -N exited ${intent.exitCode}`)
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
          baseCommit,
        ],
        forwards: forwards(migratorStores),
        timeoutMs: manifest.agents?.limits?.timeMs,
      })
      if (diff.exitCode !== 0) throw Error(`git diff exited ${diff.exitCode}`)
      await writeFile(resolve(output, 'migration.diff'), diff.stdout)
      manifest.artifacts = {
        transcript: 'migrator-transcript.log',
        ...('brokerEvidence' in result
          ? { brokerEvidence: 'broker-evidence.json' }
          : {}),
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
        stackSource?.tarball
          ? 'file:./resolved-stack.tgz'
          : `@cipherstash/stack@${manifest.stack}`,
      ])
      // PostgreSQL starts createApp only after its conversion, in behaviour().
      if (postgresUpgrade) return
      host = await isolation.openAppHost({
        actor: 'app-host',
        workspace: oracleWorkspace,
        env: env(oracleStores),
        forwards: forwards(oracleStores),
      })
    },
    async behaviour() {
      /** @type {import('../types.js').OracleCheck[]} */
      let conversion = []
      if (postgresUpgrade) {
        conversion = await postgresConversion()
        host = await isolation.openAppHost({
          actor: 'app-host',
          workspace: oracleWorkspace,
          env: env(oracleStores),
          forwards: forwards(oracleStores),
        })
      }
      const application = host
      if (!application) throw Error('App Host has not started')
      try {
        if (postgresUpgrade) {
          let freshSnapshot
          let freshSnapshotFailure
          const result = await postgresBehaviour(
            (method, args) => application.call(method, args),
            async () => {
              try {
                freshSnapshot = await assigned(oracleStores).postgresSnapshot()
              } catch (error) {
                freshSnapshotFailure = error
              }
            },
          )
          const current = await oracleSnapshot()
          result.checks.unshift(...conversion)
          result.checks.push(
            ...postgresMigrationChecks(legacySnapshot, current),
          )
          const checks = await result.mutate()
          if (freshSnapshotFailure) {
            throw Object.assign(
              Error('PostgreSQL fresh storage inspection failed', {
                cause: freshSnapshotFailure,
              }),
              {
                infrastructure:
                  isSnapshotInfrastructureError(freshSnapshotFailure),
              },
            )
          }
          checks.push(postgresFreshWriteCheck(freshSnapshot, 'new'))
          checks.push(
            ...(await migrationChecks({
              workspace,
              installedWorkspace: oracleWorkspace,
              stackVersion: manifest.stack,
              ffiRange,
              procedure,
            })),
          )
          return checks
        }
        let mutationSnapshot
        const result = await behaviour(
          (method, args) => application.call(method, args),
          async () => {
            try {
              mutationSnapshot = await assigned(oracleStores).snapshot(
                mutation.pk,
              )
            } catch (error) {
              throw Object.assign(
                new Error('Mutation Data inspection failed', { cause: error }),
                { infrastructure: isSnapshotInfrastructureError(error) },
              )
            }
          },
        )
        let current
        try {
          current = await assigned(oracleStores).snapshot()
        } catch (error) {
          throw Object.assign(
            new Error('Oracle snapshot read failed', { cause: error }),
            { infrastructure: isSnapshotInfrastructureError(error) },
          )
        }
        const comparison = noRewrite(legacySnapshot, current)
        result.checks.push(comparison)
        const checks = await result.mutate()
        checks.push(
          ...(await migrationChecks({
            workspace,
            installedWorkspace: oracleWorkspace,
            stackVersion: manifest.stack,
            ffiRange,
            mutationSnapshot,
          })),
        )
        return checks
      } finally {
        await application.close()
        host = null
      }
    },
    async close() {
      if (host) await host.close().catch(() => {})
      try {
        await isolation.stop()
      } finally {
        await disposeStores(resources)
      }
    },
  }
}
