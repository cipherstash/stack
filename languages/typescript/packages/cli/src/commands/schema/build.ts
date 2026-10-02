import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import * as p from '@clack/prompts'
import { loadStashConfig } from '../../config/index.js'
import { buildSchemasFromDatabase } from '../init/lib/introspect.js'
import type { Integration } from '../init/types.js'
import { generateClientFromSchemas } from '../init/utils.js'

// --- Command ---

export async function builderCommand(
  options: { supabase?: boolean; databaseUrl?: string } = {},
) {
  const config = await loadStashConfig({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })

  p.intro('CipherStash Schema Builder')

  // Schema builder flow — uses DB introspection to generate a client file
  const integration: Integration = options.supabase ? 'supabase' : 'postgresql'

  const defaultPath = config.client ?? './src/encryption/index.ts'

  const clientFilePath = await p.text({
    message: 'Where should we write your encryption client?',
    placeholder: defaultPath,
    defaultValue: defaultPath,
  })

  if (p.isCancel(clientFilePath)) {
    p.cancel('Cancelled.')
    return
  }

  const resolvedPath = resolve(process.cwd(), clientFilePath)

  if (existsSync(resolvedPath)) {
    const action = await p.select({
      message: `${clientFilePath} already exists. What would you like to do?`,
      options: [
        {
          value: 'keep',
          label: 'Keep existing file',
          hint: 'cancel builder',
        },
        { value: 'overwrite', label: 'Overwrite with new schema' },
      ],
    })

    if (p.isCancel(action) || action === 'keep') {
      p.cancel('Cancelled.')
      return
    }
  }

  const schemas = await buildSchemasFromDatabase(config.databaseUrl)

  if (!schemas || schemas.length === 0) {
    p.cancel('Cancelled.')
    return
  }

  const fileContents = generateClientFromSchemas(integration, schemas)

  const dir = dirname(resolvedPath)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }

  writeFileSync(resolvedPath, fileContents, 'utf-8')
  p.log.success(`Encryption client written to ${clientFilePath}`)
  p.outro('Schema ready!')
}
