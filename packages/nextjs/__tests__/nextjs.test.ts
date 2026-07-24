import { type NextRequest, NextResponse } from 'next/server'
// cts.test.ts
import { afterEach, describe, expect, it, type Mock, vi } from 'vitest'

// ---------------------------------------------
// 1) Mock next/headers before importing it
// ---------------------------------------------
vi.mock('next/headers', () => ({
  cookies: vi.fn(), // We'll override in tests with mockReturnValueOnce(...)
}))

// ---------------------------------------------
// 2) Mock logger before importing it
// ---------------------------------------------
vi.mock('../../utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  },
}))

// ---------------------------------------------
// 3) Prepare your spies for partial mocking
//    (must be declared before vi.mock("../src/"))
// ---------------------------------------------
const mockReset = vi.fn()
const mockSetCtsToken = vi.fn()

// ---------------------------------------------
// 4) Partial-mock ../src/ BEFORE importing
//    anything from that module
// ---------------------------------------------
vi.mock('../src/', async () => {
  // Re-import actual code so that only certain exports are overridden
  const actual = await vi.importActual<typeof import('../src/')>('../src/')
  return {
    ...actual,
    resetCtsToken: mockReset,
    setCtsToken: mockSetCtsToken,
  }
})

// ---------------------------------------------
// 5) Now import after the mock is declared
// ---------------------------------------------
import { cookies } from 'next/headers'
import { logger } from '../../utils/logger'
import {
  CS_COOKIE_NAME,
  type CtsToken,
  getCtsToken,
  protectMiddleware,
  resetCtsToken,
} from '../src/'

describe('getCtsToken', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('should return the parsed token if the cookie is present', async () => {
    const mockCookieValue: CtsToken = {
      accessToken: 'fake_token',
      expiry: 999999,
    }
    ;(cookies as unknown as Mock).mockReturnValueOnce({
      get: vi.fn().mockReturnValue({ value: JSON.stringify(mockCookieValue) }),
    })

    const token = await getCtsToken()

    expect(token).toEqual(mockCookieValue)
    expect(logger.debug).not.toHaveBeenCalledWith(
      'No CipherStash session cookie found in the request.',
    )
  })

  it('should return null if the cookie is not present', async () => {
    ;(cookies as unknown as Mock).mockReturnValueOnce({
      get: vi.fn().mockReturnValue(undefined),
    })

    const token = await getCtsToken()

    expect(token).toBeNull()
    expect(logger.debug).toHaveBeenCalledWith(
      'No CipherStash session cookie found in the request.',
    )
  })
})

describe('resetCtsToken', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('should delete the token cookie on the provided NextResponse', () => {
    const response = NextResponse.next()
    const mockDelete = vi.spyOn(response.cookies, 'delete')

    const updatedResponse = resetCtsToken(response)

    expect(mockDelete).toHaveBeenCalledWith(CS_COOKIE_NAME)
    expect(updatedResponse).toBe(response)
  })

  it('should create a new NextResponse if none is provided', () => {
    const response = resetCtsToken()

    expect(response).toBeInstanceOf(NextResponse)
    // Confirm the cookie is cleared
    expect(response.cookies.get(CS_COOKIE_NAME)?.value).toBe('')
  })
})

describe('protectMiddleware', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  function createMockRequest(hasCookie: boolean) {
    return {
      cookies: { has: vi.fn().mockReturnValue(hasCookie) },
    } as unknown as NextRequest
  }

  it('should call setCtsToken if oidcToken is provided and there is no session cookie', async () => {
    const mockOidcToken = 'valid_token'
    const mockReq = createMockRequest(false)

    await protectMiddleware(mockOidcToken, mockReq)

    expect(mockSetCtsToken).toHaveBeenCalledWith(mockOidcToken)
  })

  it('should reset the cts token if oidcToken is not provided but cookie is present', async () => {
    const mockReq = createMockRequest(true)

    await protectMiddleware('', mockReq)

    expect(logger.debug).toHaveBeenCalledWith(
      'The JWT token was undefined, so the CipherStash session was reset.',
    )
    expect(mockReset).toHaveBeenCalled()
  })

  it('should return NextResponse.next() if none of the conditions are met', async () => {
    const mockReq = createMockRequest(false)

    const response = await protectMiddleware('', mockReq)

    expect(response).toBeInstanceOf(NextResponse)
    expect(logger.debug).toHaveBeenCalledWith(
      'The JWT token was undefined, so the CipherStash session was not set.',
    )
  })
})
