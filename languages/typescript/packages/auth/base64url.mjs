/* @ts-self-types="./base64url.d.ts" */

// Shared base64url codec for the token-cookie value (`/cookies`) and the warmed-
// token request header (`/next`). Both transports must encode/decode
// identically, so the implementation lives here rather than being copied into
// each. Uses only WHATWG `btoa`/`atob`/`TextEncoder`/`TextDecoder` — NOT Node's
// `Buffer` — because `/next` runs in the Edge middleware runtime where `Buffer`
// is not reliably available.

/**
 * @param {string} input
 * @returns {string}
 */
export function encodeBase64Url(input) {
  // btoa works on binary strings; encode the UTF-8 bytes first so non-ASCII
  // round-trips. Token JSON is ASCII in practice but be defensive.
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i++)
    binary += String.fromCharCode(bytes[i]);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

/**
 * @param {string} input
 * @returns {string}
 */
export function decodeBase64Url(input) {
  const padded = input.replaceAll("-", "+").replaceAll("_", "/");
  const pad =
    padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
