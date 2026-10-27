# Changelog

Changes to the Go module `github.com/cipherstash/stack/languages/golang`:
the SDK (`encrypt`), the generator (`stashgen`, `cmd/stashgen`) and the
credential package (`auth`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The module is pre-1.0, so a minor version may break the API; every break is
listed under **Breaking**. Releases are tagged `languages/golang/vX.Y.Z`.

## [Unreleased]

### Added

- `Strategy.ServiceToken` returns an opaque `auth.ServiceToken` with the bearer
  and decoded workspace/service metadata. It shares acquisition, caching and
  refresh with `Strategy.Token`, which still returns a string without requiring
  that extra metadata. Neither method verifies JWT signatures locally.

- Workspace administration through `control`: CTS actors, access-key metadata
  and memberships, and ZeroKMS keysets, clients and grants. Creation secrets
  support one-shot typed transfer or byte export. Administrative writes are
  not retried, redirects are refused, and malformed inventories fail closed.

- **A two-letter word is searchable in `TextMatch`, `TextSearch` and
  `TextSearchOre` (#1309).** The EQL v4 match types index each two-letter
  word whole, beside the 3-grams of the text, so a two-letter surname such
  as "Ng" stores into a `TextMatch` field (it was refused with `ErrTerm`),
  and `Matches` with "ng" is a query (it was refused) that finds the rows
  holding the word "Ng", not "Nguyen". A query's two-letter words must be
  whole words of the row: "Mike Ng" does not find "Mike Nguyen". Text that
  cuts no token, an empty string or one letter, is still refused by
  `TextMatch` and stored with the empty filter by the search types. The
  word token is one more token per two-letter word, in the same filter, so
  someone who clusters tokens across rows can tell "Ng" from "Nguyen".
  A native `index=match` field takes no options yet (#1112), so this
  reaches Go through the EQL types only.

- **Encrypted JSON documents of Go types** (#1351). A struct, map or slice
  field tagged `encrypt_into=JsonSearch` is a document: the generated code
  marshals it with `encoding/json` when it seals it, and reads the opened
  document back into the declared type (`gensupport.GetDocument`,
  `GetDocumentPtr`), so 64-bit integers and finite `float64`s round-trip
  exactly. A pointer to one takes `null=sql`. The rest of a document comes
  back as `encoding/json` reads it: invalid UTF-8 in a string becomes
  U+FFFD, a nil map or slice is stored as JSON `null` (not `{}` or `[]`),
  and a `time.Time` inside a document is stored as RFC 3339 text in its
  own offset, which `EqAt` and the orderings compare as text. `stashgen` refuses, when it
  runs, a type `encoding/json` cannot carry both ways: an interface such as
  `any`, a struct field `encoding/json` drops (unexported, tagged
  `json:"-"`, or two writing one member), a field tagged
  `json:",string"` (stored as a JSON string, which a query by its number
  does not match), an embedded pointer to an
  unexported struct (written, never read back), a one-way `MarshalJSON` or
  `MarshalText`, a channel, a function, a scalar, or a `[]byte`. The `Fields` entry's operands are Go
  values now: `Contains`, `ContainedBy`, `EqAt`, `Lt`, `Lte`, `Gt`, `Gte`
  and `Between` take `any`,
  a `json.RawMessage` crossing as the JSON text it is and anything else
  marshalled (`gensupport.JSONText`); a `[]byte`, a type defined over
  one, or a pointer to either is refused, and so is a containment needle
  that is a Go string, a pointer to one, or writes JSON `null`. A zero
  struct field without `omitempty` narrows a containment query, so
  `Contains` on a field whose type holds a struct refuses a needle of that
  type (`gensupport.NewDocumentField`); the generated doc comments say how
  to write a needle. `encrypt.DecodeJSON[T]` reads a value a selection or
  subtree read opened into a Go type, numbers in an interface as
  `json.Number`. An error from either direction names a Go type and never
  the value.

- **Encrypted JSON documents with `stashgen`** (#1351, #1352). A
  `json.RawMessage` field tagged `encrypt_into=JsonSearch` (options:
  `ordered=$.a;$.b[*].c`, `sealed_root=false`) is stored as an
  `eql.JSONSearch` in a `public.eql_v4_json_search` column; a
  `*json.RawMessage` field takes `null=sql`. Its `Fields` entry has
  `Contains`, `ContainedBy`, `EqAt`, `Selector`, `Subtree`, `Children` and
  `ChildCount`, and `At.<Path>` per ordered path with `Lt`, `Lte`, `Gt`,
  `Gte`, `Between` and the path's own `Selector`; at a wildcard path their
  operands are compared over every match (`eql_v4.json_tree_path_query`),
  since `->` there returns an unspecified element. `encrypt.JSONSelection`
  and `encrypt.JSONRead` open the rows `->` and `eql_v4.json_tree_subtree`
  return against the request that prepared them (`OpenOne` refuses a
  wildcard read up front); `encrypt.JSONSelector`, `JSONToken` and
  `JSONTokens` bind as `text` and `text[]`, and a zero selector, token or
  token list is refused rather than bound. `JSONToken`, `JSONTokens`,
  `JSONSelection` and `JSONRead` print and log with the tokens, the
  selector and the path redacted; `encrypt.JSONValue` holds plaintext and
  prints it. A `json.RawMessage` sealed any other way stays
  bytes. `gensupport.JSON`, `TargetOptions`,
  `Declaration.Options` and the `JSON*` helpers are the generated code's.

- **Query and read an encrypted JSON document, at the record level**
  (#1350, #1352). `Cipher.QueryTerm` derives a document field's operands:
  `QueryTerm.Encoding` says what the term holds, and `QueryTerm.Text`
  carries a selector, a node's token or a read's tokens.
  `Cipher.JSONOpen` opens the rows a selector or subtree read returned
  against the request that prepared it. `record.Operator.Input` names an
  operator's input. Generated methods follow with `stashgen`.

- **The EQL types for an encrypted JSON document** (#1348):
  `eql.JSONSearch` (`public.eql_v4_json_search`), its containment needle
  `eql.JSONSearchQuery`, its ordering operand
  `eql.JSONSearchLeafQuery` and its entry `eql.JSONEntry`,
  generated from the EQL catalog. The names are the ones EQL v3 gives its
  searchable JSON document; `eql.JSON` stays the storage-only type. The
  engine stores one from the module's own plans, and `stashgen` generates
  fields tagged `encrypt_into=JsonSearch`.

- **Decimals, dates and timestamps take an order index (#1236).** An
  `encrypt.Decimal`, `encrypt.Date` or `time.Time` field takes `ore` and
  `ope`, and the generated code gives it `Lt`, `Lte`, `Gt`, `Gte` and
  `Between`. A decimal orders by value (`1.5` ties `1.50`), a date by its
  day, and a timestamp by the microsecond, truncated as its equality term
  is. The EQL types `DateOrd`, `DateOrdOpe`, `DateOrdOre`, `TimestampOrd`,
  `TimestampOrdOpe`, `TimestampOrdOre`, `NumericOrd`, `NumericOrdOpe` and
  `NumericOrdOre` are producible with `encrypt_into=`.
- **An optional field: a sealed field declared over a pointer (#1298).**
  `DOB *encrypt.Date` with `stash:"dob,encrypt_into=Date"` generates (it
  was refused as a composite, #1293), and `Decrypt` gives `nil` back for a
  `nil`. The new `null=` tag part says how `nil` is stored:
  `null=sealed` seals it as a null as long as a value of the field's type,
  so the column does not show which rows have no value; `null=sql` stores
  nothing, so the field's columns are SQL `NULL` and its member in the
  generated type is a pointer. `stashgen` picks `null=sealed` for a field
  whose type has a fixed width (a bool, a number, `encrypt.Date`,
  `time.Time`, `encrypt.Decimal`, the 128-bit integers) and whose only
  index, if any, is equality, and asks for `null=sql` to be written on any
  other: a null has an equality term and no other, and text shows its
  length. Beside equality a sealed null stores the term every nil of the
  field shares, and a generated `EqNull` method derives its `eq` query,
  which finds the rows whose value is absent. A generated `EncryptNull`
  method seals `nil` for an update of one such column, which writing SQL
  `NULL` would not store. A stored null read into a
  field that is not a pointer is an error from `Decrypt`. `-model` does not
  map a `null=sql` field yet.

### Breaking

- `ProfileStore.AccessKey` now consumes `*auth.AccessKey`, constructed with
  `auth.NewAccessKey(ownedBytes)`, instead of a string. It wipes the owned
  bytes on success and failure.

- **`eql.SteVecDocument` and `eql.SteVecQuery` are gone.** They named
  EQL v4's SteVec domains, which the engine never produced and the v4
  bundle no longer carries: in v4, `public.eql_v4_json_search` is the
  JSON tree document, `eql.JSONSearch`, and `eql.Types` lists it in
  their place.

- **An opaque struct seals as a storage blob, and reads the JSON it used
  to (#1347).** `stash:"context=...,opaque"` now seals the struct as one
  blob in vitaminc's storage profile, version 1 (`vcffi.MarshalStorage`),
  the format vitaminc keeps readable across releases and languages, where
  it sealed the JSON document `encoding/json` wrote. Rows sealed before
  still decrypt: `Decrypt` reads a value that is not a blob as JSON.
  **Run stashgen again:** generated files name
  `gensupport.GeneratedVersion2`, so a file generated before does not
  compile against this release (it would seal blobs keyed by Go field
  names that the regenerated file could not read). The generated shape
  struct names each field `vc:"name,default"`, so a field added to the
  struct later reads as its zero value from a blob sealed before it, as
  it did from JSON. A field added to a nested struct type has no such
  tag: give it a pointer type, or rows sealed before it do not decrypt.
  **Upgrade every reader before any writer:** an earlier release cannot
  read a blob, so a rolling deploy or a rollback that runs an earlier
  release after this one has sealed a row fails to decrypt that row.
  What else changes for a program: a NaN or infinite float now seals
  (JSON refused it with `ErrEncoding`); a nil slice or map comes back
  empty, not nil, from a blob; `Encrypt` refuses, as `ErrEncoding`
  wrapping `vcffi.ErrUnwritable`, a string that is not UTF-8 (JSON wrote
  U+FFFD), a value nested more than 128 levels deep, and two map keys
  whose `MarshalText` spells alike. `stashgen` refuses in an opaque
  struct `encrypt.Decimal` and `encrypt.Date` (the storage profile has no
  form for them), a type with only one of `MarshalText` and
  `UnmarshalText`, a map key that is not an integer, a string, bytes or
  text, and a type that only `MarshalJSON` carries over a struct with
  unexported fields. **Rows already sealed with an `encrypt.Decimal` or
  `encrypt.Date` in an opaque struct do not decrypt under this release**,
  since no generated file can name the field: before upgrading, decrypt
  them with the earlier release, change the field to a string (or to its
  parts), and encrypt them again; the earlier release writes JSON, which
  this release reads. A blob a later release writes is
  `encrypt.ErrStorageVersion`. This takes vcffi from the unreleased
  cipherstash/vitaminc#526 by pseudo-version; the storage format is a
  compatibility commitment only once vitaminc releases it, so no Go
  release should be cut while the pin is a pseudo-version.
- **Every order term changes: re-derive stored `ore`, `ope` and
  `ore_block` index terms.** The engine moved to vitaminc 0.8, clww-ore 0.6
  (formerly cllw-ore) and ore-rs 0.10, and both order schemes now derive
  different terms for the same value, so a query term no longer compares
  with an order term stored before. Ciphertexts and equality terms are
  unchanged.
- **An `int8`, `int16`, `uint8` or `uint16` sealed field seals at its own
  width; run stashgen again.** It used to seal as a 32-bit integer. Values
  stored before do not decrypt under the regenerated declaration: the
  engine checks the stored leaf's kind against the declared one and
  refuses an int32 leaf for an `int16` field. Equality terms are the same
  at every width, order terms are not. To keep reading stored values,
  declare the field `int32` or `uint32` (or re-encrypt them).
- **Run stashgen again.** A field's query methods are now one per operator
  the engine answers on it (`Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between`,
  `Matches`), in place of one per index (`Equality`, `Match`, `Ore`, `Ope`,
  `Query`, `JSON`). A file generated by the alpha's stashgen no longer
  compiles against this library.
- **`Cipher.Query` and `Cipher.Derive` are gone**, with the guest's
  `se_query` export. Generated methods derive terms through
  `Cipher.QueryTerm`, named by operator.
- **`gensupport.Field`** loses `Equality`, `Match`, `Ore`, `Ope`, `Query` and
  `JSON`, and gains `Term` and `Range`; `gensupport.Matches` and
  `gensupport.EQLMatches` derive match queries.
- **`stashgen.Engine.Check` returns the operators each field answers**:
  `Check(ctx, d) (map[string][]stashgen.Operator, error)`. An engine
  implemented outside this module (a wrapper, or a fake in a generator's
  tests) changes its `Check` to return them; `enginetest.Static` shows the
  table.
- **An `int8`, `uint8` or `byte` field takes no `ore` or `ope` index; drop
  the index and run stashgen again.** With 256 values, an order term ranks
  every row among 256, which a few known rows resolve to the values, the
  leak a `bool`'s order term is already refused for. The engine refuses the
  declaration as it refuses one on a `bool`, so stashgen stops at it. The
  field keeps `equality` and `Eq`; a value that must order declares a wider
  type.
- **Every ORE and OPE term changes bytes; encrypt indexed rows again.**
  Order terms now encrypt through cllw-ore's vitaminc schemes, for every
  type: integers of every width, floats, text and bytes. A term v0.1.0-alpha.1
  stored does not compare with one this release derives, and nothing
  refuses it: `Lt`, `Between` or an `ORDER BY` over a column holding the
  alpha's terms silently misses or misplaces rows. Re-derive a column's
  order terms (encrypt its rows again) before querying it.

### Added

- **The date, timestamp and numeric EQL v4 types are producible** (#1130):
  `Date` and `DateEq` from an `encrypt.Date`, `Timestamp` and `TimestampEq`
  from a `time.Time`, and `Numeric` and `NumericEq` from an
  `encrypt.Decimal`, with `encrypt_into=`. The `Eq` types answer `Eq`:
  `NumericEq` normalises the scale (`1.5 = 1.50`) and `TimestampEq` compares
  to the microsecond (truncated, never rounded), while each value opens as it was sealed. A
  `time.Time` seals its instant and opens in UTC. Their `Ord`, `OrdOpe` and
  `OrdOre` types follow (see above).
- **Every integer width, 128-bit integers, dates, timestamps and decimals
  as sealed fields** (#1144). Each integer type seals at its own width
  (`int8` as an int8, `uint16` as a uint16), so `record.Kind` and
  `gensupport` gain `Int8`, `Int16`, `Int128`, `Uint8`, `Uint16`,
  `Uint128`, `Decimal`, `Date` and `Timestamp`. A `time.Time` field seals
  as a timestamp and opens in UTC. `encrypt.Date`, `Int128`, `Uint128` and
  `Decimal` are vitaminc's `vcvalue` types, with `encrypt.DateOf`,
  `ParseInt128`, `ParseUint128` and `ParseDecimal` (which refuses NaN and
  the infinities with `ErrNonFiniteDecimal`). Equality applies to all of
  them, ORE and OPE to every integer width but 8 bits, and to decimals,
  dates and timestamps (see above). The value-kinds fixture
  test opens a record the Rust lowering sealed and derives the same terms.
- **Any built-in Go integer field takes an integer EQL type** (ADR-0002):
  an `int16` or a `uint16` into `Integer`, an `int` into `Bigint`. The
  field is sealed at the type's width and opens back into the field's
  type. A type wider than the EQL type (an `int64` into `Integer`) is range
  checked value by value, and `Encrypt` refuses a value that does not fit
  with `ErrEncoding`. `encrypt.Int128` and `Uint128` are not converted.
- **Range query types in `encrypt/eql`**, one per ordered family and order
  index: `eql.IntegerRangeOreQuery`, `eql.IntegerRangeOpeQuery`,
  `eql.TextRangeOreQuery`, `eql.TextRangeOpeQuery`, and the same for
  `smallint`, `bigint`, `date`, `timestamp`, `numeric`, `real` and `double`.
  Each holds both bounds of one `BETWEEN` (each bound the single-bound
  domain's `ob` or `op` value, in a `{v, i, lo, hi}` envelope) as the JSON
  value `eql_v4.between(column, $1::eql_v4.query_<family>_range_<ore|ope>)`
  takes, so a range binds as one parameter. The cast to the exact range
  domain is required, or the statement fails with SQLSTATE 42725. Each type
  implements `driver.Valuer`, `sql.Scanner` and JSON like the other query
  types. They are not in
  `eql.Types`, which lists stored types, and no generated method returns one
  yet: `stashgen` does not construct a range query operand, although the
  ordered EQL types are producible and expose single-bound comparisons.
- **`encrypt.MatchQuery` and `encrypt.EQLMatchQuery`**: what a `Matches`
  method returns. Each carries the term or EQL query value to bind,
  `Verify` (check decrypted rows, since a match can return false positives)
  and `TargetLimit` (size the fetch). A `TextMatch` field gets `Matches`,
  returning an `EQLMatchQuery`. Neither prints its query text, through any
  fmt verb, reflection or slog. The zero value of either returns
  `ErrEncoding` from every method, `Value` included, so it never binds as
  NULL.
- **`encrypt.Range`**: what `Between` returns, the low and high bound's
  terms.
- **`IntegerEq`, `BigintEq`, `RealEq` and `DoubleEq`**: an `int32`, `int64`,
  `float32` or `float64` field tagged `encrypt_into=` one of them gets `Eq`.
  `=` compares as PostgreSQL compares the plain types: an integer has one
  term whatever its width, and for floats `-0.0 = 0.0` and `NaN = NaN`.
- **`Smallint` and `SmallintEq`**: an `int16` field (or any Go integer
  type, range checked as for `Integer`) tagged `encrypt_into=` one of them
  seals at 16 bits; `SmallintEq` gets `Eq`, with the same equality term as
  an integer of the same value under the same column.
- **`IntegerOrd`, `SmallintOrd`, `BigintOrd`, `RealOrd`, `DoubleOrd`,
  `TextOrd` and their `OrdOpe` twins**: a field tagged `encrypt_into=` one of them gets `Lt`,
  `Lte`, `Gt` and `Gte`, and a text one `Eq` too. They store an OPE term
  that orders by ADR-0002's order key: floats as PostgreSQL's `float8`
  sorts them, text by its fold. No `Between` yet: it needs EQL v4's range
  query domains.
- **`IntegerOrdOre`, `SmallintOrdOre`, `BigintOrdOre`, `RealOrdOre`,
  `DoubleOrdOre`, `TextOrdOre` and `TextSearchOre`**: a field tagged `encrypt_into=` one of
  them gets `Lt`, `Lte`, `Gt` and `Gte` (and on text `Eq`, and on
  `TextSearchOre` `Matches`), as the `Ord` types do. They store a block ORE
  term (ore-rs's 6-bit schemes), compared by EQL v4's comparator; each
  write and each query carries a fresh nonce, so two terms of one value
  never share bytes. Text whose fold is longer than 1023 bytes or ends in
  NUL is refused, stored or queried. The engine reports their ordering
  operators through the index `ore_block` (`record.OreBlock`,
  `stashgen.IndexOreBlock`), which a struct reaches only by naming one of
  these types: it is not a tag word.
- **`TextSearch`**: a `string` field tagged `encrypt_into=TextSearch` gets
  `Eq`, `Lt`, `Lte`, `Gt`, `Gte` and `Matches`, one column for all of them.
  The stored value keeps all three terms. Text that cuts no match token,
  such as an empty string or one letter, is stored with an empty match
  filter, where `TextMatch` refuses it with `ErrTerm`: `Eq`, `Lt`, `Lte`,
  `Gt` and `Gte` find the row, and no `Matches` query does. Each query
  carries only the term its operator reads, so `Eq` and `Lt` take a
  one-letter value and `Matches` refuses one (`ErrTerm`). A two-letter
  word has its own match token, as described above. Needs the EQL v4
  SQL from this release, whose `eql_v4.query_text_search` accepts one term.
- **Ordering methods on text.** A string field with `index=ore` or
  `index=ope` gets `Lt`, `Lte`, `Gt`, `Gte` and `Between`. Text orders by its
  folded form (ADR-0002: case and accents folded, under Unicode 16), so
  `Café` and `cafe` tie and `alice` orders before `Zoe`.
- **Ordering methods on floats.** A `float32` or `float64` field with
  `index=ore` or `index=ope` gets `Lt`, `Lte`, `Gt`, `Gte` and `Between`.
  Floats order as PostgreSQL's `float8` does (ADR-0002): `-0.0` ties `0.0`,
  and every NaN is one value, above `+Inf`. A `float32` orders as the
  `float64` it widens to.
- **stashgen notices an index no generated method queries**: an `ore` or
  `ope` index on bytes (the engine answers the orderings over integers,
  floats and text only), or the second of two order indexes on a field.
  The index is still stored; the notice is on stderr and in the file.

### Changed

- **vitaminc's Go bindings at an untagged vitaminc commit (temporary).**
  `vcffi` and `vcvalue` move to vitaminc `06568ba93` on its `main`, which
  carries the storage profile (`vcffi.MarshalStorage`, from
  cipherstash/vitaminc#526); vitaminc's Go bindings have no tags, so the
  commit is the pin. One encoding changes
  with them, and it comes from vitaminc `e9c3837b` (on `main`, in no Go
  tag yet), not from the storage profile: a nil pointer to a fixed-width
  value (`(*int64)(nil)`) is written as a typed null where it was written
  as a null. The engine reads a typed null as a null, and generated code
  passes an untyped nil for a nil pointer, so this only shows in the bytes
  a hand-built `record.Source` or query input sends. The pin returns to a
  vitaminc release before this module is tagged:
  `scripts/go-release-version.mjs` refuses a final version while `go.mod`
  names a vitaminc pseudo-version.
- **An EQL v4 block ORE term is one hex string.** The `ob` of a value
  encrypted into an `_ord_ore` or `text_search_ore` EQL type is
  `"ob": "0202…"`, where it was a one-element array, and the EQL v4 bundle
  checks the shape of every `ob` and `op` it stores. A database that
  installed the EQL v4 bundle attached to `v0.1.0-alpha.1` must drop its
  stored order domains before installing the new one (EQL's upgrade note
  U-003).
- **A call whose context ends fails on its own and leaves the client
  open.** A cancelled or timed-out call used to close the `encrypt.Client`,
  or the `auth` profile behind its strategy, for every later caller, and a
  request whose deadline passed while it waited for the client closed it
  before running. Now a call waiting for the client leaves the queue with
  the context's error; a ZeroKMS request in flight is cancelled, and the
  error matches both the context's error and `ErrTransport`; a device
  session's refresh in flight finishes in the background, for up to 10
  seconds, so a rotated refresh token is never lost; and the client stays
  open. A client or profile still closes itself (`ErrState`) when the
  guest traps, or when a call runs on for 30 seconds after its context
  ended.
- **A call no longer holds the client across a ZeroKMS round trip.** The
  guest returns each ZeroKMS request to the client instead of performing it
  through a blocking host import (`transport_send` is gone; the guest's one
  import is `token_get`). The client performs the request with its lock
  free, so other callers run meanwhile, then resumes the call. A call whose
  context ends between those steps returns the context's error, matching
  `ErrTransport` too, and the guest drops the paused call, wiping what it
  held; the client stays open.
  The token is fetched once per call, before its first step and outside
  the lock. That includes a call the guest answers from its cache (a query
  term on a loaded keyset, a cached keyset lookup), which never asked for
  a token before, so a token source sees one request per such call; one
  that fails is still reported only when the guest needs the token. At
  most 64 calls that can reach ZeroKMS are in progress at once (the
  guest's cap on paused calls); one past that waits for another to finish,
  as it waited for the client before. This is the step loop an
  edge runtime's host needs, where `fetch` cannot block.
- **stashgen refuses a match index on an index-only field**
  (`stash:"name,index=match"` with no `encrypt`). A match query's rows are
  checked by decrypting them, and such a field stores no ciphertext.
- A query with a nil cipher returns `ErrEncoding` from generated code as from
  the library.
- stashgen's refusal of an EQL type it cannot produce names the issue that
  tracks the blocker, in place of telling you to wait for vitaminc 0.6.
