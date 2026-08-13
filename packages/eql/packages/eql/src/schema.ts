import { schemaIds, schemaNames } from './generated/schema-manifest'

export { schemaIds, schemaNames }

export type EqlSchemaName = (typeof schemaNames)[number]

export function schemaId(name: EqlSchemaName): string {
  return schemaIds[name]
}
