/**
 * A test double that can see the WIRE FORMAT.
 *
 * `createMockSupabase` records the arguments handed to each builder method and
 * stops there. That pins per-element *encryption* but is structurally blind to
 * *encoding*: postgrest-js still has to serialize those arguments into a query
 * string, and that is where an unescaped `"` inside an encrypted envelope turns
 * `in.(…)` into a request PostgREST rejects. A mock that never builds a URL can
 * never catch it.
 *
 * So this harness runs the REAL `PostgrestClient` with a `fetch` that captures
 * the request URL and answers with canned rows. No database, no `DATABASE_URL`
 * gate — but the operand is byte-for-byte what a live PostgREST would receive.
 *
 * Use it for anything whose correctness lives in the emitted query string
 * (`in`, `not.in`, `or`); keep using `createMockSupabase` for everything else.
 */

import { PostgrestClient } from '@supabase/postgrest-js'
import type { SupabaseQueryBuilder } from '@/supabase/types'

export type WirePostgrest = {
  /** Structurally a supabase client: `.from(table)` → a query builder. */
  client: { from(table: string): SupabaseQueryBuilder }
  /** Every request URL issued, in order. */
  urls: string[]
  /** The decoded operand for `column` on the last request, e.g. `in.("…","…")`. */
  operandFor(column: string): string
}

export function createWirePostgrest(resultData: unknown = []): WirePostgrest {
  const urls: string[] = []

  const fetchImpl = (input: unknown): Promise<Response> => {
    urls.push(
      typeof input === 'string'
        ? input
        : String((input as { url: string }).url ?? input),
    )
    return Promise.resolve(
      new Response(JSON.stringify(resultData), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
  }

  const client = new PostgrestClient('http://wire.test', {
    fetch: fetchImpl as unknown as typeof fetch,
  })

  return {
    client: client as unknown as WirePostgrest['client'],
    urls,
    operandFor(column: string): string {
      const last = urls.at(-1)
      if (last === undefined) throw new Error('no request was issued')
      // `searchParams.get` percent-decodes; PostgREST sees exactly this.
      const value = new URL(last).searchParams.get(column)
      if (value === null) {
        throw new Error(
          `no filter emitted for column "${column}" in ${new URL(last).search}`,
        )
      }
      return value
    },
  }
}
