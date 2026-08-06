// Fixture for the "event loop exits naturally" integration test —
// AutoStrategy variant.
//
// Same shape as event-loop-exit-jsbacked.cjs but with NO `opts.strategy`,
// so the Rust side builds an AutoStrategy from env credentials. There is
// no JS-backed auth Channel on this path, so this script proves the
// previous process-wide `JS_CHANNEL` static (now removed) is no longer
// pinning libuv either.

require('dotenv/config')
const { newClient, encrypt, decrypt } = require('@cipherstash/protect-ffi')

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
  const client = await newClient({ encryptConfig })

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

  console.log('ok')
})().catch((err) => {
  console.error(err)
  process.exitCode = 1
})
