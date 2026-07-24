---
'@cipherstash/stack': patch
---

Fix `encryptedDynamoDB`'s EQL v2 read path, which failed against a v3-configured
client — the case the v2 read support exists for.

`decryptModel` and `bulkDecryptModels` forwarded the table to the encryption
client unconditionally. The second argument is only meaningful to the typed EQL
v3 client, which resolves it against its own reconstructor map; a legacy v2
table is not in that map, so the call failed with:

```
[eql/v3]: decryptModel received a table this client was not initialized with
```

That contradicted the adapter's documented contract — writes are EQL v3 only,
but decrypt keeps accepting a v2 table so previously stored items stay readable.
In practice the failure hit exactly the customers the compatibility promise was
written for: upgraded to a v3 schema, with v2 items still in the table.

The table is now forwarded only when it is an EQL v3 table. A v2 table takes the
table-less form, and the client derives the table from the payloads themselves.

Both paths are covered by a credential-free test asserting what the adapter
forwards, so a regression no longer depends on a live-credential integration run
to surface.
