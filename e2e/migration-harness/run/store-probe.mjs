import { randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createIsolation } from '../isolation.mjs'
import { createStoreSet, disposeStores } from './real-stores.mjs'

// This command uses only Node built-ins, just like an uninstalled Fixture App.
// PostgreSQL's SSL negotiation proves the forwarded endpoint speaks Postgres;
// DynamoDB's ListTables proves the assigned endpoint is an empty Store Set.
const forwardingProbe = `
const net = require('node:net');
async function main() {
  await new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: 5432 });
    socket.setTimeout(10000, () => socket.destroy(Error('Postgres forward timed out')));
    socket.once('error', reject);
    socket.once('connect', () => socket.write(Buffer.from([0, 0, 0, 8, 4, 210, 22, 47])));
    socket.once('data', (data) => {
      socket.destroy();
      if (!['S', 'N'].includes(data.toString())) reject(Error('Invalid Postgres negotiation'));
      else resolve();
    });
  });
  let failure;
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const response = await fetch('http://127.0.0.1:8000', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-amz-json-1.0',
          'x-amz-target': 'DynamoDB_20120810.ListTables',
          authorization: 'AWS4-HMAC-SHA256 Credential=migrationfixture/20261109/us-east-1/dynamodb/aws4_request, SignedHeaders=host;x-amz-date, Signature=0',
          'x-amz-date': '20261109T000000Z',
        },
        body: '{}',
        signal: AbortSignal.timeout(2000),
      });
      if (!response.ok) throw Error('DynamoDB forward returned ' + response.status);
      const result = await response.json();
      if (!Array.isArray(result.TableNames) || result.TableNames.length !== 0)
        throw Error('Assigned DynamoDB endpoint contains unexpected tables');
      return;
    } catch (error) {
      failure = error;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  throw failure;
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
`

/** @type {import('./real-stores.mjs').Resource[]} */
const resources = []
const isolation = createIsolation()
const workspace = await mkdtemp(join(tmpdir(), 'migration-store-probe-'))
try {
  const proof = await isolation.prove()
  if (!proof.verified) throw Error('Store probe requires proven isolation')
  /** @type {Record<string,unknown>} */
  const results = {}
  for (const actor of ['migrator', 'oracle']) {
    const stores = await createStoreSet({
      runId: randomUUID(),
      actor,
      eqlBundle: fileURLToPath(
        new URL(
          '../../../packages/eql/packages/eql/sql/cipherstash-encrypt.sql',
          import.meta.url,
        ),
      ),
      resources,
    })
    const verified = await stores.verify()
    const forwarded = await isolation.exec({
      actor: actor === 'oracle' ? 'app-host' : 'migrator',
      workspace,
      env: stores.env,
      forwards: stores.forwards,
      command: ['node', '-e', forwardingProbe],
      timeoutMs: 60_000,
    })
    if (forwarded.exitCode !== 0)
      throw Error(
        `Assigned ${actor} store forwarding failed: ${forwarded.stderr}`,
      )
    results[actor] = { ...verified, assignedLoopbackForwarding: true }
  }
  console.log(JSON.stringify(results))
} finally {
  try {
    await isolation.stop()
  } finally {
    await disposeStores(resources)
    await rm(workspace, { recursive: true, force: true })
  }
}
