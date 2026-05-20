import { type Result, withResult } from '@byteslice/result'
import type { ProtectClient, SearchTerm } from '@cipherstash/protect'
import { handleError } from '../helpers'
import type { ProtectDynamoDBError } from '../types'
import {
  DynamoDBOperation,
  type DynamoDBOperationOptions,
} from './base-operation'

/**
 * @deprecated Use `protectClient.encryptQuery(terms)` instead and extract the `hm` field for DynamoDB key lookups.
 *
 * @example
 * ```typescript
 * // Before (deprecated)
 * const result = await protectDynamo.createSearchTerms([{ value, column, table }])
 * const hmac = result.data[0]
 *
 * // After (new API)
 * const [encrypted] = await protectClient.encryptQuery([{ value, column, table, queryType: 'equality' }])
 * const hmac = encrypted.hm
 * ```
 */
export class SearchTermsOperation extends DynamoDBOperation<string[]> {
  private protectClient: ProtectClient
  private terms: SearchTerm[]

  constructor(
    protectClient: ProtectClient,
    terms: SearchTerm[],
    options?: DynamoDBOperationOptions,
  ) {
    super(options)
    this.protectClient = protectClient
    this.terms = terms
  }

  public async execute(): Promise<Result<string[], ProtectDynamoDBError>> {
    return await withResult(
      async () => {
        const searchTermsResult = await this.protectClient
          .createSearchTerms(this.terms)
          .audit(this.getAuditData())

        if (searchTermsResult.failure) {
          throw new Error(`[protect]: ${searchTermsResult.failure.message}`)
        }

        return searchTermsResult.data.map((term) => {
          if (typeof term === 'string') {
            throw new Error(
              'expected encrypted search term to be an EncryptedPayload',
            )
          }

          if (term?.k !== 'ct' || !term.hm) {
            throw new Error('expected encrypted search term to have an HMAC')
          }

          return term.hm
        })
      },
      (error) =>
        handleError(error, 'createSearchTerms', {
          logger: this.logger,
          errorHandler: this.errorHandler,
        }),
    )
  }
}
