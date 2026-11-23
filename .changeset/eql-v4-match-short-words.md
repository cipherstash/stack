---
'@cipherstash/eql': minor
---

**EQL v4's match types now index each two-letter word as a whole word, so a two-letter surname such as "Ng" is searchable** (#1309). `eql-bindings`' `EqlMatch` is the match configuration of `TextMatch`, `TextSearch`, and `TextSearchOre`. `EqlMatch` now turns on Stack Encrypt's `MatchOptions::short_words`.

A stored value's filter contains the 3-grams of the whole text. A 3-gram is a run of three characters, such as "mik" in "Mike". The filter now also contains each word of exactly two characters, as one more token. Words are split on space, comma, semicolon, colon, and exclamation mark.

The word token is hashed under a domain of its own. Like a 3-gram, it sets 6 positions in the same 2048-bit filter.

- "Ng" can now be stored in `TextMatch`. Before, `TextMatch` refused it, because "Ng" has no 3-gram.
- A `TextSearch` value of "Ng" now stores a filter, not the empty filter.
- `@@` with the query "ng" finds the rows that contain the word "Ng", such as "Ng", "Mike Ng", and "NG, Anna". The query does not find "Nguyen".

A query asks for its two-letter words only when the whole query is one two-letter word. A query of three characters or more asks for its 3-grams alone, as it would without word tokens. So "Mike Ng" finds "Mike Ng" and "Mike Nguyen". A name typed in part, such as "ke Ng" or "san fr", still finds its row.

Every query path follows this rule, so a query's filter and its verify agree. The paths are:

- a field reference's `matches`;
- the query twins' `EncryptTarget`;
- the by-name query dispatch that a binding runs;
- `verify`.

A query twin's filter has a new field type, `v4::terms::QueryBloomFilter`. A query twin is the struct that contains a query's terms. The new type is the `bf` of `TextMatchQuery`, `TextSearchMatchQuery`, `TextSearchOreMatchQuery`, `TextSearchQuery`, and `TextSearchOreQuery`. `QueryBloomFilter` has the JSON and JSON Schema of `BloomFilter`. Only fields of the `v4` module change, and that module is not released yet.

Text with no token at all, such as one letter or nothing, is handled as before. `TextMatch` refuses it. The search types store it with the empty filter.

**The v4 match format now includes short-word tokens.** A filter of text holding a two-letter word gains that word's bits; text with none derives the filter it did. EQL v4 is unreleased, so this is the format it ships with: a v4 value written by an earlier build that holds a two-letter word lacks the word's bits, and a query naming that word does not find it until the value is re-encrypted.

**What it reveals.** Each stored value gains one more token for each two-letter word it contains. The token uses the same pseudorandom function (PRF), the same filter, and the same containment rule. No two-character piece of a longer word is indexed.

The word token is unique to the word. Someone who groups tokens across rows can tell the rows that contain "Ng" from the rows that contain "Nguyen", and count them. Without the word token, they see only the 3-gram `" ng"` that both names share.

A query of one two-letter word shows which word it asks for. A longer query sends no word token.

No SQL function changes (one doc comment in the bundle is reworded), and the TypeScript types do not change.
