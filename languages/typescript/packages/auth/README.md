# @cipherstash/auth

[![npm version](https://img.shields.io/npm/v/@cipherstash/auth?style=for-the-badge)](https://www.npmjs.com/package/@cipherstash/auth)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discord](https://discord.com/invite/5qwXUFb6PB)

Native Node.js bindings for authenticating with [CipherStash](https://cipherstash.com) services using the [OAuth 2.0 Device Authorization](https://datatracker.ietf.org/doc/html/rfc8628) flow.

## Installation

```bash
npm install @cipherstash/auth
```

Prebuilt native binaries are included for:

- macOS (x64, ARM64)
- Linux (x64 glibc, x64 musl, ARM64 glibc)
- Windows (x64)

## Usage

```js
const { beginDeviceCodeFlow } = require("@cipherstash/auth");

const result = await beginDeviceCodeFlow(region, clientId);

// Show the user the code and URL
console.log(`Go to ${result.verificationUri} and enter code: ${result.userCode}`);

// Or open the browser automatically
result.openInBrowser();

// Wait for the user to authorize
const auth = await result.pollForToken();
console.log(`Token expires in ${auth.expiresIn} seconds`);
```

The token is saved to `~/.cipherstash/auth.json` automatically and is never exposed to JavaScript.

## API

### `beginDeviceCodeFlow(region, clientId)`

Starts the OAuth 2.0 Device Authorization flow. Returns a `Promise<DeviceCodeResult>`.

### `DeviceCodeResult`

| Property / Method | Description |
|---|---|
| `userCode` | The code the user enters at the verification URI |
| `verificationUri` | The URL the user visits to authorize |
| `verificationUriComplete` | URL with the code pre-filled |
| `expiresIn` | Seconds until the device code expires |
| `openInBrowser()` | Opens the verification URI in the default browser |
| `pollForToken()` | Polls until the user completes authorization. Returns `Promise<AuthResult>` |

### `AuthResult`

| Property | Description |
|---|---|
| `expiresAt` | Absolute epoch timestamp (seconds) when the token expires |
| `expiresIn` | Seconds until the token expires |

## Error handling

Errors thrown by the native module include a machine-readable `.code` property:

```js
try {
  await result.pollForToken();
} catch (err) {
  console.error(err.code);    // e.g. "EXPIRED_TOKEN"
  console.error(err.message); // Human-readable description
}
```

## License

See [LICENSE](https://github.com/cipherstash/cipherstash-suite/blob/main/packages/stack-auth/LICENSE).
