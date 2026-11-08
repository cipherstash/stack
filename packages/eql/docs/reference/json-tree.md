# EQL v4: encrypted JSON documents

A `public.eql_v4_json_search` column stores one encrypted JSON document.
Without the key, PostgreSQL can test containment, extract an entry by path,
compare the value at a path, read a subtree, and count children. This page
gives the SQL for each. Every parameter in it is a value the SDK derives from
the column and the path: a query, a selector, or a list of tokens. No
plaintext path reaches the database.

For what the stored document and each query reveal, read [What an encrypted
JSON tree reveals](json-tree-leakage.md). For the element and predicate
functions, read their sections in the [EQL functions
reference](eql-functions.md).

## On this page

- [Storing a document](#storing-a-document)
- [Typed operands](#typed-operands)
- [Containment](#containment)
- [Extracting an entry by selector](#extracting-an-entry-by-selector)
- [Comparing the value at a path](#comparing-the-value-at-a-path)
- [Testing that a path exists](#testing-that-a-path-exists)
- [Reading a subtree](#reading-a-subtree)
- [Children and child count](#children-and-child-count)
- [One array element, and a whole predicate](#one-array-element-and-a-whole-predicate)
- [What the SQL cannot do](#what-the-sql-cannot-do)
- [What is authenticated](#what-is-authenticated)

## Storing a document

Type the column as `public.eql_v4_json_search`:

```sql
CREATE TABLE customers (
  id      bigserial PRIMARY KEY,
  profile public.eql_v4_json_search
);
```

The stored value is a JSON object with three parts:

- the document's header `h`;
- one encrypted entry for each object, array, and scalar;
- the containment projection `q`.

The entries The entries are stored in a random order,
and the order says nothing about the document. By default the root entry
is sealed: its ciphertext is the whole document, so a reader can open the
document in one step.

Which paths carry an ordering term is set in the SDK, with the column's
options. By default no path is ordered.

## Typed operands

`public.eql_v4_json_search` is a PostgreSQL domain over `jsonb`. So
PostgreSQL resolves `column OP $1` against the native `jsonb` operator
unless the operand's type says otherwise. Cast every operand to its EQL
type:

```sql
-- correct: the operand's type selects the eql_v4 operator
WHERE profile @> $1::eql_v4.query_json
WHERE (profile -> $1::text) > $2::eql_v4.query_json_leaf

-- wrong: resolves to jsonb @> jsonb, and matches nothing
WHERE profile @> $1
```

The same rule makes PostgreSQL's own `jsonb` functions accept the column.
They run over the stored envelope, not the document, and return false or
NULL with no error. [Native jsonb functions read the
envelope](json-tree-leakage.md#native-jsonb-functions-read-the-envelope)
lists them.

## Containment

`@>` tests whether the document contains the needle. `<@` tests the
reverse. The needle is an `eql_v4.query_json`, derived by the SDK from a
JSON value. Equality of a scalar at a path is a containment needle too: a document
with `{"name": "Ada"}` at the path.

```sql
SELECT id, profile FROM customers WHERE profile @> $1::eql_v4.query_json;
SELECT id, profile FROM customers WHERE profile <@ $1::eql_v4.query_json;
```

Containment is answered by `jsonb @>` over the projection
`eql_v4.json_tree_query(profile)`. A GIN index on that expression serves
both operators:

```sql
CREATE INDEX ON customers USING gin ((eql_v4.json_tree_query(profile)) jsonb_path_ops);
```

Two containment needles on one array can be answered by different
elements. To test several members of one element together, use the element
function in the [section below](#one-array-element-and-a-whole-predicate).

## Extracting an entry by selector

`->` returns the entry at a path, as a `public.eql_v4_json_entry`. `->>`
returns the same entry as text. Both are still encrypted: the client opens
them. The operand is the path's selector, as text.

```sql
SELECT id, profile -> $1::text  AS entry      FROM customers;
SELECT id, profile ->> $1::text AS entry_text FROM customers;
```

Every element of an array shares its array's selector. So at a path that
runs through an array, such as `$.tags[*]`, `->` returns one of the
elements, and which one is not specified. The entries are stored in a
random order since #1379. For every element, use `eql_v4.json_tree_path_query`. It returns one
row per match:

```sql
SELECT id, x.entry
FROM customers AS c
CROSS JOIN LATERAL eql_v4.json_tree_path_query(c.profile::jsonb, $1::text) AS x(entry);
```

`json_tree_path_query` and `json_tree_path_exists` take the column as
`jsonb`, so the recipes cast it.

## Comparing the value at a path

An entry at an ordered path compares against an `eql_v4.query_json_leaf`,
the ordering operand the SDK derives from a value at that path. The four
comparisons and a range use the natural operators on `->`. Order rows with
`eql_v4.ord_term`, never with the entry itself: `ORDER BY profile -> $1`
sorts by ciphertext.

```sql
-- $1 is the selector of the path. $2 and $3 are the bounds.
SELECT id, profile FROM customers
WHERE (profile -> $1::text) >= $2::eql_v4.query_json_leaf
  AND (profile -> $1::text) <= $3::eql_v4.query_json_leaf
ORDER BY eql_v4.ord_term(profile -> $1::text) ASC NULLS LAST;
```

A functional btree index on the ordering term serves the comparisons:

```sql
CREATE INDEX ON customers USING btree (eql_v4.ord_term(profile -> 'the selector'::text));
```

At a path through an array, `->` compares one unspecified element. To ask
whether any element satisfies the bound, write the test over every match:

```sql
SELECT c.id FROM customers AS c
WHERE EXISTS (
  SELECT 1
  FROM eql_v4.json_tree_path_query(c.profile::jsonb, $1::text) AS x(entry)
  WHERE x.entry > $2::eql_v4.query_json_leaf
);
```

Sorting rows by a path through an array needs a rule the application
chooses, such as `MIN` or `MAX` over the matches. Do not assume the first
element.

A comparison is of the ordering term. Text compares after its case and
accents are folded, and numbers compare as 64-bit floats. A path with no
ordering term, or no node, compares as NULL.

## Testing that a path exists

```sql
SELECT id FROM customers WHERE eql_v4.json_tree_path_exists(profile::jsonb, $1::text);
```

The operand is the path's selector. A position in the path reads as the
wildcard, so the test is for the path through any element.

## Reading a subtree

A subtree read returns a node and every entry beneath it, so the client
can open a part of the document without the whole.

The SDK derives one token for each concrete path to read. A wildcard such as `$.items[*]` expands to one token per element, up
to a bound, plus one probe token at the bound. The bound is 64 by
default. The list is capped at 8,192 tokens. The second argument is the walk budget.

```sql
SELECT c.id, w.entry
FROM customers AS c
CROSS JOIN LATERAL eql_v4.json_tree_subtree(c.profile, $1::text[], $2::integer) AS w(entry);
```

The signature is `eql_v4.json_tree_subtree(e public.eql_v4_json_search,
tokens text[], budget integer DEFAULT 64) RETURNS SETOF
public.eql_v4_json_entry`. Its rules:

- A read that would return more than `budget` rows, counted over every
  token, returns the sealed root alone instead. The client then opens the
  whole document and picks out the values it asked for. This is the root
  fallback.
- A budget of `0` never falls back.
- A document whose root is not sealed has no root to fall back to, so its
  reads return in full whatever the budget.
- A token that names no node returns no row.
- The budget bounds the row count of one read. It does not bound the size
  of a response.

Group the rows by `id` before opening them: each row is one entry of one
document, and the client opens a document's entries together.
`eql_v4.json_tree_subtree_indexed` is the same read with `k`, the token's
place in the list, on every row.

## Children and child count

`eql_v4.json_tree_children(e, token)` returns the entries directly below
one node, one row per child. The rows are in ordinal order: position
order for an array, random order for an object. `eql_v4.json_tree_child_count(e,
token)` returns how many there are. The operand is one token for a
concrete path. Neither takes a wildcard.

```sql
SELECT c.id, k.entry
FROM customers AS c
CROSS JOIN LATERAL eql_v4.json_tree_children(c.profile, $1::text) AS k(entry);

SELECT id, eql_v4.json_tree_child_count(profile, $1::text) FROM customers;
```

The count is `0` for a scalar or an empty container. It is NULL for a token that names no node. It is also NULL for the
root of a document whose root is sealed, because that root's children
chain from nothing. Do not convert
NULL to `0`. The count is a count of stored entries: it is not an
authenticated proof that no child was withheld.

## One array element, and a whole predicate

Two containment needles, or two comparisons, on one array can be
satisfied by different elements.
`eql_v4.json_tree_element_match(e, p eql_v4.query_json_elements)` asks
whether one element satisfies every member of the predicate. The [EQL functions
reference](eql-functions.md#one-array-element-in-eql-v4-eql_v4json_tree_element_match)
describes it, with its folding, its bound, and the SQLSTATE it raises.

`eql_v4.json_tree_match(e, p eql_v4.query_json_predicate)`, and the
operator `@@`, take a whole jsonpath predicate compiled by the SDK as one
parameter. The [same
reference](eql-functions.md#a-compiled-predicate-in-eql-v4-eql_v4json_tree_match)
describes the tree, where its answer differs from `jsonb_path_match`, and
why no index serves it.

## What the SQL cannot do

- **Open a child bound to its parent.** The SQL returns children, but
  opening one child scalar so that it is checked against its parent is
  not implemented. To inspect one child, the client fetches the parent's
  subtree and opens it. That transfers more data, and reveals a different
  set of tokens.
- **Return plaintext of every match.** `json_tree_path_query` returns
  encrypted entries. The supported way to grouped plaintext for a path
  through an array is a subtree read with a wildcard bound.
- **Open a container entry on its own.** Since #1379 each container's tag
  covers its children's tags, so a container returned without its
  subtree fails to open. Read the subtree.

## What is authenticated

A node's tag covers its children's tags. So a subtree read proves that
the rows beneath the returned node are the ones sealed there, each in
its place. A read does not prove four things:

- that a result set is complete;
- that a value is absent;
- that the row is the one the application asked for;
- that the data is fresh. The database can withhold whole
results or probes. [What is authenticated](json-tree-leakage.md#what-is-authenticated) gives
the detail. ADR-0010, in `packages/stack-encrypt/docs/adr/`, records why
a container's membership, order, and length are not authenticated.

## Tell us what is missing

If this page is missing something you needed, [open an
issue](https://github.com/cipherstash/stack/issues/new).
