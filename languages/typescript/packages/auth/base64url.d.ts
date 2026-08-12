/* tslint:disable */
/* eslint-disable */

/*
 * Shared base64url codec used by both the `/cookies` token-cookie value and the
 * `/next` warmed-token header. WHATWG-only (Edge-runtime safe). See base64url.mjs.
 */

/** Encode a UTF-8 string as unpadded base64url. */
export declare function encodeBase64Url(input: string): string;

/** Decode an unpadded base64url string back to UTF-8. */
export declare function decodeBase64Url(input: string): string;
