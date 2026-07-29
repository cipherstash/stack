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

The current v3 table is now forwarded on every read, legacy storage included:
the legacy path reconstructs the v2 envelope around it, and the reconstructor
map is keyed by the current schema either way. (Schema authoring is EQL v3-only,
so there is no longer any such thing as a v2 table object to pass.)

Both paths are covered by a credential-free test asserting what the adapter
forwards, so a regression no longer depends on a live-credential integration run
to surface.
