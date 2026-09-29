# Explicit credentials

A runnable example of `stackencrypt.NewCredentials`: the application
supplies every credential itself, and nothing is read from `CS_*` variables
or the developer profile. Use this shape when the client key lives in a
secrets manager, when one process talks to more than one workspace, or when
the environment is not yours to set. `../` shows the default,
`AutoCredentials`.

## Running it

The secrets come from a directory holding two files, the way a Kubernetes or
Docker secret is mounted:

| File | Contents |
|---|---|
| `client-key` | The client key: the `CS_CLIENT_KEY` hex form, or the base64 in `secretkey.json`. |
| `access-key` | An access key (`CSAK…`) for the workspace. |

```bash
mise run go:stackencrypt:example:explicit -- \
    -secrets-dir /run/secrets \
    -client-id <client id> \
    -workspace-crn <workspace CRN>
```

Or build both guests and run it yourself from `bindings/go`:

```bash
mise run wasm:guest:build wasm:auth-guest:build
cd bindings/go && go run ./stackencrypt/example/explicit -secrets-dir ... -client-id ... -workspace-crn ...
```

Optional flags: `-cts-host` pins the authentication endpoint (default: from
the workspace CRN), `-zerokms-url` pins ZeroKMS (default: from the token),
and `-require-locked-memory` refuses to run on memory that cannot be locked
in RAM.

## What it shows

- **Where secrets come from.** `fileSecrets` reads mounted files. Replace it
  with your secrets manager's client; the rest does not change. The client
  key goes straight into `NewClientKey`, which takes ownership of the bytes,
  and `NewClient` wipes them.
- **Who owns what.** The application opens the credential guest
  (`stackauth.OpenWithoutProfile`) and the access-key strategy, and closes
  them after the client. The client asks the strategy for a token on every
  request, and the strategy re-exchanges the access key as tokens expire.
- **Locked memory.** With `-require-locked-memory` the credential guest is
  opened with `stackauth.RequireLockedMemory()` and the client with
  `WithRequireLockedMemory()`, so both guests stay locked. The client's
  printed memory state covers both.
- **A key is for one client.** Passing the same credentials to a second
  `NewClient` is refused with `ErrCredentialsConsumed`, before any request.
