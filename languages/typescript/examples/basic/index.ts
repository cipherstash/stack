import 'dotenv/config'
import readline from 'node:readline'
import { client, users } from './encrypt'

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
})

const askQuestion = (): Promise<string> => {
  return new Promise((resolve) => {
    rl.question('\n👋Hello\n\nWhat is your name? ', (answer) => {
      resolve(answer)
    })
  })
}

async function main() {
  const input = await askQuestion()

  const encryptResult = await client.encrypt(input, {
    column: users.name,
    table: users,
  })

  if (encryptResult.failure) {
    throw new Error(`[encryption]: ${encryptResult.failure.message}`)
  }

  const ciphertext = encryptResult.data

  console.log('Encrypting your name...')
  console.log('The ciphertext is:', ciphertext)

  const decryptResult = await client.decrypt(ciphertext)

  if (decryptResult.failure) {
    throw new Error(`[encryption]: ${decryptResult.failure.message}`)
  }

  const plaintext = decryptResult.data

  console.log('Decrypting the ciphertext...')
  console.log('The plaintext is:', plaintext)

  // Demonstrate bulk encryption
  console.log('\n--- Bulk Encryption Demo ---')

  const bulkPlaintexts = [
    { id: '1', plaintext: 'Alice' },
    { id: '2', plaintext: 'Bob' },
    { id: '3', plaintext: 'Charlie' },
  ]

  console.log(
    'Bulk encrypting names:',
    bulkPlaintexts.map((p) => p.plaintext),
  )

  const bulkEncryptResult = await client.bulkEncrypt(bulkPlaintexts, {
    column: users.name,
    table: users,
  })

  if (bulkEncryptResult.failure) {
    throw new Error(`[encryption]: ${bulkEncryptResult.failure.message}`)
  }

  console.log('Bulk encrypted data:', bulkEncryptResult.data)

  rl.close()
}

main()
