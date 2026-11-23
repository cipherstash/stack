---
"@cipherstash/eql": patch
---

`eql-bindings` (the Rust crate released with this package): a borrowed `&Identifier` is now a Stack Encrypt context, the same context as the `Identifier`. A program can hold one identifier and pass `&column` to the cipher-directed API, or build a `NonEmpty<&Identifier>` for a term, without a clone. The stored EQL (Encrypt Query Language) types still take their `NonEmpty<Identifier>` by value.

The EQL types also gain `contexts()`, from Stack Encrypt. The method shows the context each stored field is sealed and indexed under, before any key is requested. The SQL bundle and the TypeScript types do not change.
