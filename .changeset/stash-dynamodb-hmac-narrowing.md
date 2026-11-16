---
'stash': patch
---

The `stash-dynamodb` skill's query examples now narrow the `encryptQuery` result before reading `hm`. The previous `result.data.hm` did not type-check, because the result type also covers ciphertexts, strings and `null`.
