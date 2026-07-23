---
'stash': patch
---

Skills refresh for the EQL v3 collapse (ships in the `stash` tarball):

- `stash-dynamodb`: audited decrypt now works on the typed client —
  `client.decryptModel(item, table).audit({ … })` — so the old "use
  `Encryption({ config: { eqlVersion: 3 } })` for audited decrypts" caveat is
  removed. Encrypt/write is EQL v3 only; decrypt still reads existing v2 items.
- `stash-encryption`: canonical examples use `Encryption` (with `EncryptionV3`
  noted as a deprecated alias); the DynamoDB notes state encrypt is v3-only while
  decrypt still reads v2.
