---
'@cipherstash/eql': minor
---

**EQL v4's match types index each two-letter word whole, so a two-letter surname such as "Ng" is searchable** (#1309). `eql-bindings`' `EqlMatch`, the match configuration of `TextMatch`, `TextSearch` and `TextSearchOre`, turns on Stack Encrypt's `MatchOptions::short_words`: beside the 3-grams of the whole text, every word of exactly two characters (words split on space, comma, semicolon, colon and exclamation mark) is one more token, the word itself, hashed under a domain of its own and folded into the same 2048-bit filter by the same 6 positions. "Ng" now stores into `TextMatch` (it was refused, cutting no 3-gram), a `TextSearch` holding "Ng" stores a filter rather than the empty one, and `@@` with the query "ng" finds the rows holding the word "Ng" ("Ng", "Mike Ng", "NG, Anna"), not "Nguyen". A query's two-letter words must be whole words of the row, so "Mike Ng" does not find "Mike Nguyen". Text that still cuts no token (one letter, or none) is refused by `TextMatch` and stored with the empty filter by the search types, as before.

**The v4 match format now includes short-word tokens.** A filter of text holding a two-letter word gains that word's bits; text with none derives the filter it did. EQL v4 is unreleased, so this is the format it ships with: a v4 value written by an earlier build that holds a two-letter word lacks the word's bits, and a query naming that word does not find it until the value is re-encrypted.

**What it reveals.** One more token per two-letter word, under the same PRF, in the same filter, by the same containment rule, so no new class of leakage. The token is specific to the word: someone who clusters tokens across rows can tell the rows holding the word "Ng" from those holding "Nguyen", where before only the boundary trigram `" ng"` they share was visible. No bigram of a longer word is indexed.

No SQL function changes (one doc comment in the bundle is reworded), and the TypeScript types do not change.
