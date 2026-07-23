---
'stash': patch
---

Trim the leading comment block from near-miss statements reported by the Drizzle
migration rewriter (`stash eql migration --drizzle`, `stash eql install`).

The broad near-miss scan is anchored on the previous `;`, so a
`SET DATA TYPE … USING …` it could not safely repair was quoted back to the user
with every preceding comment and blank line glued to its front — in a file
opening with a comment block, that meant the whole header. The reported
statement is now the offending statement alone. Detection is unchanged; only the
text shown to the user is affected.

Keeps this rewriter in sync with its sibling in `@cipherstash/wizard`.
