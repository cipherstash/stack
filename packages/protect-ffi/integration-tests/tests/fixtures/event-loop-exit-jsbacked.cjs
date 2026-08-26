// Fixture for the "event loop exits naturally" integration test.
//
// Creates a Client using a JS-supplied `opts.strategy`, performs one
// encrypt + decrypt, then returns. Does NOT call process.exit(). If the
// Node event loop drains correctly, this script terminates on its own;
// if anything (e.g. an unref'd auth Channel) is still pinning libuv,
// the parent test times out and kills it.

require('dotenv/config')
const { newClient, encrypt, decrypt } = require('@cipherstash/protect-ffi')

/** @type {import('@cipherstash/protect-ffi').EncryptConfig} */
const encryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'string',
        indexes: { unique: {} },
      },
    },
  },
}
;(async () => {
  // Use the wasm-inline build of @cipherstash/auth — it has no native
  // binary dep, works on any Node target, and lets us exercise the
  // `opts.strategy` (JsBacked) code path with a real getToken.
  // The CRN is passed whole: auth parses the region out of it (versions before
  // 0.39 took only the `<region>.<provider>` segment).
  const { AccessKeyStrategy } = await import('@cipherstash/auth/wasm-inline')
  const accessKey = process.env.CS_CLIENT_ACCESS_KEY
  const workspaceCrn = process.env.CS_WORKSPACE_CRN
  if (!accessKey || !workspaceCrn) {
    throw new Error(
      'event-loop-exit-jsbacked fixture needs CS_CLIENT_ACCESS_KEY and CS_WORKSPACE_CRN',
    )
  }
  // Since 0.41 `create` returns a `Result<AccessKeyStrategy, AuthFailure>`.
  // Unwrapped here — the envelope has no `getToken`, and this fixture's whole
  // job is to prove the event loop drains after a real JsBacked round-trip, so
  // a construction failure has to fail loudly rather than as a contract error.
  const created = AccessKeyStrategy.create(workspaceCrn, accessKey)
  if (created.failure) {
    throw new Error(
      `AccessKeyStrategy.create failed (${created.failure.type}): ${created.failure.error.message}`,
    )
  }
  const strategy = created.data

  const client = await newClient({ encryptConfig, strategy })

  const ciphertext = await encrypt(client, {
    plaintext: 'event-loop-exit-test@example.com',
    table: 'users',
    column: 'email',
  })

  const plaintext = await decrypt(client, { ciphertext })
  if (plaintext !== 'event-loop-exit-test@example.com') {
    console.error(`round-trip mismatch: got ${plaintext}`)
    process.exitCode = 2
    return
  }

  // No explicit process.exit(). The presence of an unref'd auth Channel
  // (the fix under test) is what lets Node terminate cleanly here.
  console.log('ok')
})().catch((err) => {
  console.error(err)
  process.exitCode = 1
})
