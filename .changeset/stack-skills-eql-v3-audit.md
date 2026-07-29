---
'stash': patch
---

Skills refresh for the EQL v3 collapse (ships in the `stash` tarball):

- `stash-dynamodb`: audited decrypt now works on the typed client —
  `client.decryptModel(item, table).audit({ … })` — so the old "use
  a separate nominal client for audited decrypts" caveat is removed.
  Encrypt/write is EQL v3 only; legacy DynamoDB reads pass a v3 table with
  `{ storedEqlVersion: 2 }`.
- `stash-encryption`: canonical examples use `Encryption` and the generic
  `EncryptionClient<S>` type; the DynamoDB notes state encrypt is v3-only while
  native decrypt still reads stored v2 payloads.
