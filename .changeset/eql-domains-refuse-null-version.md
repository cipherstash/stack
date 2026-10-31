---
'@cipherstash/eql': patch
---

The stored and query-operand domains (`eql_v3_*`, `eql_v4_*`, `eql_v3.query_*`, `eql_v4.query_*`) now refuse a payload whose `v` is JSON `null`. The CHECK compared `v` with the bundle's version, and a comparison with `null` is NULL, which a CHECK lets through, so such a payload fitted both a v3 and a v4 domain. The range domains already refused it. A NULL value still fits every domain.
