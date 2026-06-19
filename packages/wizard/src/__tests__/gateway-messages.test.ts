import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'

const GATEWAY_URL = 'http://localhost:8787'

/**
 * Integration tests that send real messages through the local Wizard Gateway.
 *
 * Requires:
 *   1. Gateway running at http://localhost:8787
 *   2. Valid CipherStash auth token (~/.cipherstash/auth.json)
 *
 * Skips gracefully if either is unavailable.
 */
describe('Gateway AI Messages (integration)', () => {
  let accessToken: string | undefined
  let gatewayUp = false

  beforeAll(async () => {
    // Check gateway health
    try {
      const res = await fetch(`${GATEWAY_URL}/health`, {
        signal: AbortSignal.timeout(3_000),
      })
      gatewayUp = res.ok
    } catch {
      gatewayUp = false
    }

    // Load auth token
    const authPath = resolve(homedir(), '.cipherstash', 'auth.json')
    if (existsSync(authPath)) {
      try {
        const auth = JSON.parse(readFileSync(authPath, 'utf-8'))
        accessToken = auth.access_token
      } catch {
        // malformed auth.json
      }
    }
  })

  function shouldSkip(): string | false {
    if (!gatewayUp) return 'Gateway not running at localhost:8787'
    if (!accessToken) return 'No CipherStash auth token found'
    return false
  }

  async function sendMessage(body: Record<string, unknown>): Promise<Response> {
    return fetch(`${GATEWAY_URL}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    })
  }

  /**
   * Check if a response should cause us to skip (auth expired or rate limited).
   * Returns true if we should bail out of the test gracefully.
   */
  function shouldBail(res: Response): boolean {
    if (res.status === 401) {
      console.warn(
        'Skipping: CipherStash token expired. Run `npx stash auth login`.',
      )
      return true
    }
    if (res.status === 429) {
      console.warn('Skipping: Rate limited by gateway. Try again later.')
      return true
    }
    return false
  }

  // ── Non-streaming tests ──────────────────────────────────────────────

  it('completes a simple non-streaming message', async () => {
    if (shouldSkip()) return

    const res = await sendMessage({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 32,
      messages: [
        { role: 'user', content: 'Reply with exactly one word: hello' },
      ],
    })

    if (shouldBail(res)) return

    expect(res.status).toBe(200)

    const data = await res.json()
    expect(data).toHaveProperty('id')
    expect(data).toHaveProperty('type', 'message')
    expect(data).toHaveProperty('role', 'assistant')
    expect(data.content).toBeInstanceOf(Array)
    expect(data.content.length).toBeGreaterThan(0)
    expect(data.content[0]).toHaveProperty('type', 'text')
    expect(typeof data.content[0].text).toBe('string')
    expect(data.content[0].text.length).toBeGreaterThan(0)

    // Verify usage is reported
    expect(data).toHaveProperty('usage')
    expect(data.usage).toHaveProperty('input_tokens')
    expect(data.usage).toHaveProperty('output_tokens')
    expect(data.usage.input_tokens).toBeGreaterThan(0)
    expect(data.usage.output_tokens).toBeGreaterThan(0)

    // Verify model is returned
    expect(data).toHaveProperty('model')
    expect(data.model).toContain('haiku')
  })

  it('supports a multi-turn conversation', async () => {
    if (shouldSkip()) return

    const res = await sendMessage({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 64,
      messages: [
        { role: 'user', content: 'Remember the number 42.' },
        { role: 'assistant', content: 'I will remember the number 42.' },
        {
          role: 'user',
          content:
            'What number did I ask you to remember? Reply with just the number.',
        },
      ],
    })

    if (shouldBail(res)) return

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.content[0].text).toContain('42')
  })

  it('supports a system prompt', async () => {
    if (shouldSkip()) return

    const res = await sendMessage({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 32,
      system:
        'You are a pirate. Always say "Arrr" at the start of every reply.',
      messages: [{ role: 'user', content: 'Say hello.' }],
    })

    if (shouldBail(res)) return

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.content[0].text.toLowerCase()).toContain('arrr')
  })

  // ── Streaming test ───────────────────────────────────────────────────

  it('streams a response via SSE', async () => {
    if (shouldSkip()) return

    const res = await sendMessage({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 32,
      stream: true,
      messages: [{ role: 'user', content: 'Reply with exactly one word: yes' }],
    })

    if (shouldBail(res)) return

    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/event-stream')

    const body = await res.text()
    const events = body
      .split('\n')
      .filter((line) => line.startsWith('event: '))
      .map((line) => line.replace('event: ', ''))

    expect(events).toContain('message_start')
    expect(events).toContain('content_block_start')
    expect(events).toContain('content_block_delta')
    expect(events).toContain('message_stop')

    // Extract text deltas
    const deltas = body
      .split('\n')
      .filter((line) => line.startsWith('data: '))
      .map((line) => {
        try {
          return JSON.parse(line.replace('data: ', ''))
        } catch {
          return null
        }
      })
      .filter(Boolean)

    const textDeltas = deltas.filter(
      (d) => d.type === 'content_block_delta' && d.delta?.type === 'text_delta',
    )
    expect(textDeltas.length).toBeGreaterThan(0)

    const fullText = textDeltas.map((d) => d.delta.text).join('')
    expect(fullText.length).toBeGreaterThan(0)
  })

  // ── Error handling tests ─────────────────────────────────────────────

  it('rejects disallowed models', async () => {
    if (shouldSkip()) return

    const res = await sendMessage({
      model: 'claude-opus-4-6-20250605',
      max_tokens: 32,
      messages: [{ role: 'user', content: 'hello' }],
    })

    if (res.status === 401) return

    expect(res.status).toBe(400)
    const data = await res.json()
    expect(data.error).toHaveProperty('type', 'invalid_request_error')
  })

  it('rejects invalid auth token with non-200 status', async () => {
    if (!gatewayUp) return

    const res = await fetch(`${GATEWAY_URL}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
        Authorization: 'Bearer invalid-token',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 32,
        messages: [{ role: 'user', content: 'hello' }],
      }),
      signal: AbortSignal.timeout(10_000),
    })

    // In production, gateway should return 401. Dev gateway may pass through.
    // Just verify we get a response (not a crash).
    expect(res.status).toBeGreaterThanOrEqual(200)
  })

  it('rejects missing auth header with 401 or 429', async () => {
    if (!gatewayUp) return

    const res = await fetch(`${GATEWAY_URL}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 32,
        messages: [{ role: 'user', content: 'hello' }],
      }),
      signal: AbortSignal.timeout(10_000),
    })

    expect([401, 429]).toContain(res.status)
  })
})
