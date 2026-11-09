import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { cp, readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { promisify } from 'node:util'

/** Resolve once per invocation; Iteration/Loop callers reuse this value.
 * @param {{source:string,root:string,output:string}} options */
export async function resolveStack({ source, root, output }) {
  const exec = promisify(execFile)
  if (source === 'tree' || source.endsWith('.tgz')) {
    let tarball = resolve(source)
    if (source === 'tree') {
      const result = await exec(
        'npm',
        ['pack', '--json', '--pack-destination', output],
        { cwd: resolve(root, 'languages/typescript/packages/stack') },
      )
      tarball = resolve(output, JSON.parse(result.stdout)[0].filename)
    }
    const digest = createHash('sha256')
      .update(await readFile(tarball))
      .digest('hex')
    const result = await exec('tar', ['-xOf', tarball, 'package/package.json'])
    const manifest = JSON.parse(result.stdout)
    if (
      manifest.name !== '@cipherstash/stack' ||
      typeof manifest.version !== 'string'
    )
      throw Error('Tarball is not @cipherstash/stack')
    const destination = resolve(output, 'resolved-stack.tgz')
    if (tarball !== destination) await cp(tarball, destination)
    return {
      version: manifest.version,
      digest,
      tarball: destination,
      install: 'file:./resolved-stack.tgz',
    }
  }
  const result = await exec('npm', [
    'view',
    `@cipherstash/stack@${source}`,
    'version',
    '--json',
  ])
  const resolved = JSON.parse(result.stdout)
  const version = Array.isArray(resolved) ? resolved.at(-1) : resolved
  if (
    typeof version !== 'string' ||
    !/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(version)
  )
    throw Error('Could not resolve exact Stack version')
  return { version, install: version }
}
