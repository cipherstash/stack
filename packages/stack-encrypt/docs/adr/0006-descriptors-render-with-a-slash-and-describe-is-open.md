---
status: accepted
date: 2026-10-04
extends: ADR-0004
---

# Descriptors render with `/`, a column is a pair, and `Describe` is open

The ZeroKMS descriptor is the string a data-key request carries and the one
ZeroKMS binds into the key tag and writes in its retrieval log. Stack Encrypt
renders it from a context's parts, and the module docs call the rendering
frozen, because a change strands every key issued under the old one. This
ADR records a change to that rendering, made on purpose, and the two
abstractions that came with it.

## The problem

Three spellings of "the `users.email` column" were in use at once:

- The `#[derive(EncryptFrom)]` macro's `struct = User, context = "users"`
  form joined the prefix and the field name into one text part,
  `"users/email"`.
- The Go binding took the same joined string from a struct tag and sent it as
  one part.
- EQL's `eql-bindings` (#971) bound the pair `("users", "email")`, because
  EQL's `Identifier` *is* a table and a column.

One part and two parts are different contexts, so the Rust derive, the Go
binding and EQL could not read each other's rows or match each other's
search terms, and nothing failed until someone tried. On the descriptor side
the pair rendered `users|email` with `|` as the list separator, which read
nothing like the column it named.

Underneath, two concepts were being conflated: a *context* (any parts a
caller seals under, arbitrary) and an *identifier* (what the data is, with a
fixed shape). Issue #1049 and the review of #1050 named the split.

## Options considered

1. **Keep `|`, keep the joined string.** Make the derive and Go the standard
   and have EQL join its identifier into one part. Rejected: EQL's
   identifier is structurally two things, and joining them means a `/` in a
   table or column name silently changes which column a value belongs to.
2. **The pair everywhere, `/` as the separator, no escaping.** Readable, but
   a text part containing `/` would render exactly like two parts: the
   literal `"users/email"` and the pair `("users", "email")` would derive
   the same key.
3. **The pair everywhere, `/` as the separator, and escape any text part
   that could read as another form.** A part containing `/`, `(`, `)`, a
   control character or an invisible format character (a zero-width or
   bidirectional mark, which would print as another name in the log), or
   beginning with `b64:`, a digit or `-`, renders as
   `b64:` plus URL-safe base64. The standard base64 alphabet contains `/`,
   so it could not be used.

## Decision

Option 3. In detail:

- `Descriptor::SEPARATOR` is `/`. Escaped parts use URL-safe base64. The
  rendering is otherwise unchanged and remains frozen from this point.
- A column is the pair. The derive's `struct = .., context = "<prefix>"`
  form binds a field under `("<prefix>", "<field>")`. A `context = ".."`
  literal on a field is one text part, exactly as written, and renders
  escaped if it contains `/`. The derive still knows no tables (ADR-0003); a
  consumer whose prefix is a table gets EQL's shape from it.
- **`Describe` is an open trait** for a value whose parts are a descriptor
  of its own, the identity data is keyed under. An implementor returns a
  `Description`, built from a first part so it cannot be empty, and never
  writes rendered text; `Descriptor::from_piece` is the only renderer. That
  is what makes an open trait safe as a key-derivation input: two
  implementors render alike only when their parts are alike, and no
  implementor can inject a separator. `to_context` is what the type's
  `IntoContext` returns, so the AAD and the descriptor are one tree. It is
  open rather than sealed because the renderer, not the implementor list,
  carries the safety property, and a consumer's own column or document type
  is the expected implementor.
- **`Label`** is the first-class `Describe`: a path of plain segments whose
  `Display` is its descriptor and parses back losslessly. It is how a direct
  consumer of the crate names its data; EQL's `Identifier` is a two-segment
  `Label` in shape. The Go binding has the same type and the same segment
  rule, held together by one fixture both test suites read.
- An own context in a declaration tree is any `NonEmpty<impl IntoContext>`,
  not only a `&'static str` (ADR-0004, revised in place).

## Consequences

- `stack-encrypt` 0.1.0 was published with the `|` rendering before this
  landed. Any key minted through 0.1.0 renders its descriptor differently
  from the same context under this rendering and cannot be retrieved by it.
  A reader who finds `users|email` in a ZeroKMS log is looking at a 0.1.0
  key.
- **This ships as 0.2.0**, with `stack-encrypt-derive` in the same version
  group. The first revision of #1050 deferred the bump — one known consumer,
  aware of the change — on the assumption that the release tooling would
  bump on the next release. It would not: the root release-plz line is
  publish-only, and a stack-* version moves only when a pull request edits
  `Cargo.toml`. The bump also has a consumer that needs it to be a specific
  number: `eql-bindings`' `stack-encrypt` feature (#971) names the
  stack-encrypt version it compiles against, and that version has to be one
  that carries `Describe`, `Description` and `Label`, which 0.1.0 does not.
  Cargo rejects a `version` requirement the in-tree path dependency does not
  satisfy, so the bump has to land here, before #971 can name it.
- A `/` inside a name is legal but ugly: it renders escaped. `Label` refuses
  such a segment instead, so a consumer who wants a readable log uses a
  `Label` and finds out at construction.
- Text and bytes with the same content, and signed and unsigned integers of
  one width, still render alike (documented coarseness, unchanged). The
  rendering is one-to-one over part *trees* up to that coarseness, not over
  every encoding.
