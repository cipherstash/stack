import { type Result, withResult } from '@byteslice/result'
import { encryptQueryBulk, type QueryPayload } from '@cipherstash/protect-ffi'
import { logger } from '../../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../../..'
import type { LockContext } from '../../../identify'
import type { Client, EncryptedSearchTerm, SearchTerm } from '../../../types'
import { noClientError } from '../..'
import { getErrorCode } from '../../helpers/error-code'
import { inferIndexType } from '../../helpers/infer-index-type'
import { ProtectOperation } from '../base-operation'

/**
 * @deprecated Use `BatchEncryptQueryOperation` instead.
 * This class is maintained for backward compatibility only.
 */
export class SearchTermsOperation extends ProtectOperation<
  EncryptedSearchTerm[]
> {
  constructor(
    private client: Client,
    private terms: SearchTerm[],
  ) {
    super()
  }

  public withLockContext(
    lockContext: LockContext,
  ): SearchTermsOperationWithLockContext {
    return new SearchTermsOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<EncryptedSearchTerm[], ProtectError>> {
    logger.debug('Creating search terms (deprecated API)', {
      count: this.terms.length,
    })

    return await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const queries: QueryPayload[] = this.terms.map((term) => ({
          plaintext: term.value,
          column: term.column.getName(),
          table: term.table.tableName,
          indexType: inferIndexType(term.column),
        }))

        const encryptedTerms = await encryptQueryBulk(this.client, {
          queries,
          unverifiedContext: metadata,
        })

        return this.terms.map((term, index) => {
          if (term.returnType === 'composite-literal') {
            return `(${JSON.stringify(JSON.stringify(encryptedTerms[index]))})`
          }
          if (term.returnType === 'escaped-composite-literal') {
            return `${JSON.stringify(`(${JSON.stringify(JSON.stringify(encryptedTerms[index]))})`)}`
          }
          return encryptedTerms[index]
        })
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}

export class SearchTermsOperationWithLockContext extends ProtectOperation<
  EncryptedSearchTerm[]
> {
  constructor(
    private operation: SearchTermsOperation,
    private lockContext: LockContext,
  ) {
    super()
    this.auditMetadata = (operation as any).auditMetadata
  }

  public async execute(): Promise<Result<EncryptedSearchTerm[], ProtectError>> {
    const lockContextResult = await this.lockContext.getLockContext()
    if (lockContextResult.failure) {
      return { failure: lockContextResult.failure }
    }

    const { ctsToken, context } = lockContextResult.data
    const op = this.operation as any

    return await withResult(
      async () => {
        if (!op.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const queries: QueryPayload[] = op.terms.map((term: SearchTerm) => ({
          plaintext: term.value,
          column: term.column.getName(),
          table: term.table.tableName,
          indexType: inferIndexType(term.column),
          lockContext: context,
        }))

        const encryptedTerms = await encryptQueryBulk(op.client, {
          queries,
          serviceToken: ctsToken,
          unverifiedContext: metadata,
        })

        return op.terms.map((term: SearchTerm, index: number) => {
          if (term.returnType === 'composite-literal') {
            return `(${JSON.stringify(JSON.stringify(encryptedTerms[index]))})`
          }
          if (term.returnType === 'escaped-composite-literal') {
            return `${JSON.stringify(`(${JSON.stringify(JSON.stringify(encryptedTerms[index]))})`)}`
          }
          return encryptedTerms[index]
        })
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
