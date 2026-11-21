# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The predicate grammar** (#1459): the SQL/JSON path predicates the JSON
  index can answer, read from text into an `Expression`
  (`predicate::parse`), moved out of `stack-encrypt` unchanged so that
  `stack_encrypt::predicate!` reads a predicate at compile time with the
  engine's own parser. A refusal is a `PredicateError`: its kind, the
  construct in the grammar's words (`predicate::construct`) and the byte
  offset, never text from the predicate. The rules that refuse a construct
  the index cannot answer whatever the variables hold are here too
  (`Comparison::refuse_not_equal_at_wildcard`, `PathAt::element_member`,
  `check_filter`, `Comparison::check_filter_condition`,
  `single_equality`), so the engine and the macro apply one definition.
  `MAX_DEPTH` (127), the depth of a document the index reads, moves here
  as the depth a predicate's paths are read to; `stack-encrypt`'s
  stored-format bound is the same constant.

- **The crate** (#1687): the JSONPath subset that `stack-encrypt`'s JSON
  index addresses, moved out of `stack-encrypt` unchanged so that
  `stack-encrypt-derive` can check a field's declared paths at compile
  time with the same grammar. It holds `JsonPath`, `Segment`,
  `JsonPathError`, and the JSON string decoder a quoted name is read with
  (`json_string`). `stack-encrypt` re-exports the three types at
  `stack_encrypt::json`. Three items are new to the public surface, because
  the engine now builds paths across the crate boundary: `JsonPath::push`,
  `From<Vec<Segment>> for JsonPath`, and `JsonPath::names_a_position`.
  The `diagnostics` feature gives `JsonPathError` its `miette::Diagnostic`
  and `ErrorPayload`; `stack-encrypt` turns it on, and the derive leaves it
  off.
