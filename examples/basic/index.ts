import 'dotenv/config'
import readline from 'node:readline'
import { client, users } from './encrypt'
import { createContact, getAllContacts } from './src/queries/contacts'

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

  // Demonstrate Supabase integration with CipherStash encryption
  console.log('\n--- Supabase Integration Demo ---')

  try {
    // Example: Create a new contact (would insert into encrypted Supabase table)
    console.log('Creating encrypted contact...')
    const newContact = {
      name: 'John Doe',
      email: 'john@example.com',
      role: 'Developer', // This field will be encrypted using CipherStash
    }

    // Note: This would fail in this basic example since we don't have actual Supabase setup
    // but shows the pattern for encrypted Supabase usage
    console.log('Contact data to encrypt:', newContact)

    // Example: Fetch contacts (would decrypt results from Supabase)
    console.log('Fetching encrypted contacts...')
    // const contacts = await getAllContacts()
    // console.log('Decrypted contacts:', contacts.data)
  } catch (error) {
    console.log(
      'Supabase demo skipped (no actual Supabase connection in this basic example)',
    )
  }

  rl.close()
}

main()
