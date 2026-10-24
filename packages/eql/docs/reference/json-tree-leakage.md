# What an encrypted JSON tree reveals

`public.eql_v4_json_tree` (EQL v4) stores a JSON document so that PostgreSQL can answer containment, path extraction, ordering at chosen paths and subtree reads without the key. Every value, key name and container sits inside an AES-256-GCM ciphertext under the document's data key, and nothing on this page shows the text of one. What the database can see is **structure**, and a great deal of it: which paths a row has and how many times, the order the nodes are stored in, which (path, value) pairs repeat across rows, and lengths. Each item below is what one query capability or one storage choice costs. Read this before you put a column on it, and decide the two options at the end with it in mind.

## On this page

- [What a stored row shows](#what-a-stored-row-shows)
- [What a query shows](#what-a-query-shows)
- [What is authenticated](#what-is-authenticated)
- [Compared with EQL v3 (`public.eql_v3_json_search`)](#compared-with-eql-v3-publiceql_v3_json_search)
- [The two options that change the picture](#the-two-options-that-change-the-picture)

## What a stored row shows

Someone who holds the column and no key, such as a database administrator, a backup, or an attacker with a copy of the table, learns the following from each row. "Across rows" means a comparison between rows of the same column. No selector, value selector or ordering term links one column to another; the header names the keyset, which is the same for every column it seals.

| field | what it reveals |
|---|---|
| `s`, the path selector on every node | **Which paths the row has, and how many nodes sit at each.** A selector is a keyed hash of the path, the same in every row of the column, so two rows with a selector in common hold the same path. Key names are inside the hash and not readable. Array elements share their array's selector, so `$.tags[0]` and `$.tags[1]` look alike, but each element is its own entry: the number of entries carrying `$.tags[*]`'s selector is the length of `$.tags` (the total over every array at that path, when the path runs through another array). |
| the order of the entries in `sv` | **The row's shape.** Entries are stored in depth-first order, the root first, each node followed by everything beneath it, and an object's members in the sorted order of their key names. So a row's sequence of selectors fixes its shape exactly: two rows with the same sequence have the same tree with the same key names, and two rows that differ show where. Which selector's path sits under which is not written down, but it is the same in every row, so an observer comparing rows learns it, and with it each row's parent and child relations and the node count of every subtree. Siblings stored in sorted key order also show, across rows, **the alphabetical order of sibling key names** (for example that the key behind one selector sorts before the key behind another), which narrows guesses at what each selector names. |
| `q`, the containment projection: one `{s, vs}` pair per node, nested by array element, in the same order | **Whether two rows hold the same value at the same path**, through the value selector `vs`, a keyed hash of the path and the value (for an object or an array, of its kind alone). So at each path the database sees which rows agree and how often each value occurs: a frequency histogram of every path, and whether one row's document contains another's. Not the value itself, and not whether two different paths hold the same value. **Which nodes sit inside the same array element**, through the nesting, for every element that is an object or an array. That grouping is what makes containment exact for arrays of objects, and it is the one thing this format reveals that v3 did not. |
| `p`, the parent tag below the chain's heads | Nothing beyond the entry order on its own. It is salted by the document's `iv`, so the same position in two rows is unrelated bytes, and it does not say which entry is the parent. Which entries carry no `p` does show: with the sealed root on, those are the root's direct members, and since everything beneath a member follows it, **the node count of each top-level field's subtree** can be read off a single row exactly. With the sealed root off, only the root lacks one. |
| `x`, the self tag on every entry | Nothing on its own. It is a hash of the entry's own token salted by the document's `iv`, so it is unrelated bytes in every row and links no entry to another, and since every entry carries one, its presence marks none. Given a token, it is how the database finds that token's node in any row. |
| each ciphertext's length, and the number of entries | **The node count**, and for each node the length of its key name (for an object member) plus, for a scalar, the length of its value, exactly, less the AEAD's fixed overhead. A string's length in bytes and a number's length in digits are therefore visible per node. With the sealed root on, the root entry's length is the document's length as JSON. |
| `op`, the ordering term, only on number and string leaves at the paths the index orders | **The order of that leaf's value among every row that holds one, and which rows hold equal values.** The term is order-preserving encryption (CLLW OPE) under one key per column, so leaves at two ordered paths compare with each other too. It is deterministic and not a random value: two values whose encodings share leading bytes (for a string, its first characters) get terms that share leading bytes, so the term also shows how long that common prefix is. A term's presence at an ordered path also says the leaf is a number or a string. By default no path is ordered; see the options below. |
| `h`, the header | The keyset the data key was minted under, the data key's identifier (unique to the row), and whether the root is sealed. `v` and `i` are the version and the table and column identifier every EQL value carries. |

Not revealed at rest: any value's or key name's text, and whether two different paths hold the same value. Revealed at rest, by the entry order, although no field stores it: the shape of every row, the parent of every node, every array's length, and the sorted order of sibling key names.

## What a query shows

A query hands the database a term derived from the plaintext it asks about, and the database's answer is visible to it. Each query type reveals the following, in addition to the rows it returns.

- **Containment (`@>`, `<@`), and equality at a path, which is sent as a containment needle.** The needle's own projection: the selectors of its paths, the value selectors of its nodes, and its element grouping. So the database learns which paths and which (path, value) pairs you asked about, and which rows hold them.
- **Path extraction (`->`, `->>`, `json_tree_path_query`, `json_tree_path_exists`).** The selector of the path asked. A position in the path reads as the wildcard, so a position is not sent. The entry returned is a ciphertext.
- **Ordering at a path (`<`, `<=`, `>`, `>=`).** The path's selector and the bound's own ordering term, which compares with the stored terms exactly as they compare with each other: the database learns the bound's place in the order of the stored values at every ordered path, and whether it equals one. `ORDER BY ord_term(…)` sends no term and shows nothing the stored terms do not.
- **A subtree read (`json_tree_subtree`, `json_tree_children`, `json_tree_child_count`).** A **token** for exactly the node the path names, which the client derives from the path alone. Reading `$.profile.address.city` sends that leaf's token and nothing that covers `$.profile`. No token over a top-level field or an array leaves the client unless that field or array is itself what is read.
  - **A wildcard** (`$.items[*].price`) is expanded by the client into one token per concrete path, up to a bound `N` (64 by default, set by the caller), plus a **probe** token per wildcard level for the element at index `N`. A probe that finds an element means the array is longer than the bound, and the read fails rather than return part of the answer. So the database learns which of the `N + 1` nodes exist in each row, which gives each array's length up to `N` (the entry order already shows it), and the structure beneath each element it finds. It learns nothing about the elements' sibling fields. In a row where a probe finds an element, the database also walks that element's subtree, although the read then fails. Two wildcard levels send `N² + N + 1` tokens.
  - **What a token is.** A capability over the structure of its node's subtree in *every row of the column*: whoever holds it can find that node in any row (through its self tag `x`), see how the nodes beneath it nest, link each one to its parent, and derive the tokens of the nodes beneath. It opens no value. Tokens are column-wide and do not expire, so a token sent once is useful to the database for as long as the column lives. Send a token to the database in a query and nowhere else.
  - **The root.** A read of `$` sends the root's token, and a read of anything below `$` does not. With the sealed root on (the default) that token covers no document's structure: it finds the root entry, whose ciphertext is the document, and nothing beneath it, since the top-level fields chain from nothing. With it off, the root's token covers every row's whole document.
  - **`json_tree_children` and `json_tree_child_count`** take one token, of any node a path names, and send nothing else. Under the sealed root the root's token enumerates nothing (its count is NULL), for the same reason.

## What is authenticated

Only the ciphertext `c`. Opening an entry verifies that it was sealed under this keyset, for this column, under the data key its row's header names (a fresh one for every row), with the selector `s` and the position `j` it is opened with; a ciphertext moved into another row or column, or opened under another selector or position, fails. Nothing in it names a row, so an entry that travels with its own row's header still opens; see below. When the client opens a whole document it takes each entry's position from its place in `sv`, so a moved, swapped or re-labelled entry fails to open. The selectors, the projection, the parent tags, the self tags, the ordering terms, the header's sealed-root flag, and which entries a row holds are not authenticated, by the same rule every EQL stored value follows (ADR 0010 in `packages/stack-encrypt/docs/adr`).

The consequence to design around: tampering with those fields changes **which rows a query returns, where a walk stops, and which entries of a row an extraction or a walk hands back**. An entry the database returns from `->` or a walk carries its own `s` and `j`, and the header it carries names the data key, so a decrypted value is always one that was sealed in this column. The client also checks that it is the entry it asked for, from what it derived for the query, and refuses anything else (`JsonWrongEntry`):

- **`->`.** The entry must carry the selector the client derived for the path. Another path's entry, such as the row's `$.bonus` returned for `$.salary`, is refused, and so is the sealed root returned for a field (it opens to the whole document); the root is accepted only when `$` itself was asked for.
- **A subtree read.** The node each token names, returned at depth 0, must carry that path's selector and, in its decrypted label, the key or position the path ends in (the root, for `$`). Every row beneath it must sit at the next position `j` after the row before it, with no gap, and carry the selector of its parent's path extended by its own decrypted key (or the wildcard, for an array element). A row of another path, another position of the same array, a dropped, truncated or repeated row, and a row whose parent is not among the rows are refused. Each row's self tag `x` must also be the one the client recomputes from the token it sent, or, below depth 0, from its parent's token and the row's own selector and label. The self tags are not authenticated, and the database holds every token a read sends and every row's `iv`, so it can write any self tag it likes: the `x` check is a consistency check, which catches a corrupted row or a server that walked wrongly, not a substitution. The selector, the position `j` and the label, which the AAD and the ciphertext cover, are the security check. A read of a wildcard whose array is longer than the bound fails rather than return part of the list, both when the rows are walked and when they fall back to the sealed root.

What the checks do not cover, by design:

- **Which row an entry comes from.** Nothing in an entry names its row, so another row's `$.salary`, returned with that row's header, opens; that is the rule every EQL stored value follows (ADR 0010).
- **Which element a node sits under.** Every element of an array shares its selector, and no field a row binds says which element a node belongs to, so a read of `$.items[1].price` can be answered with `$.items[0].price` of the same row (its self tag rewritten), and opens to that element's price.
- **Which nodes a row holds.** Nothing in a row says how many nodes a read should find, so a database can withhold rows: a read answered with none opens as no node at the path (`None`), and a wildcard read answered with some elements' rows left out opens to the rest. A node it does return is checked as above.

A query's result is not integrity-protected as a whole: each decrypted value is genuine and at a path with the selector asked for, but which row it came from, under which element, and whether anything was left out, is the database's word.

## Compared with EQL v3 (`public.eql_v3_json_search`)

| observer sees | v3 (`ste_vec`) | v4 (`json_tree`) |
|---|---|---|
| which paths a row has | yes | yes |
| which (path, value) pairs a row has | yes | yes |
| node count | yes, two entries per node | yes, one entry per node |
| array lengths | yes | yes, from how many entries carry the element selector |
| size of every subtree | yes: each path entry's ciphertext is the subtree under it | no ciphertext spans a subtree, but its node count follows from the entry order, and its size is the sum of its entries' lengths |
| parent and child relation | inferable from subtree sizes and co-occurrence across rows | not stored, but inferable from the entry order and co-occurrence across rows; exact for top-level fields under the sealed root |
| whether two rows have the same shape | yes, selectors are column-deterministic | yes, selectors are column-deterministic and entries are stored in depth-first order |
| which leaves sit in the same array element | no | yes, through the projection's nesting: the one new disclosure, required for exact containment, bounded to array elements |
| equal values in sibling elements | ciphertexts equal | ciphertexts differ |
| ordering terms | on scalar leaves, with no per-path choice | only at the paths the index orders; none by default |
| a subtree read | reveals the selector asked | reveals a token for exactly the node asked for (one per concrete path, and one probe per wildcard level), and with it that node's shape in every row for the life of the column |

## The two options that change the picture

- **`sealed_root`** (default on). The root entry's ciphertext is the whole document, so a full read is one decryption and no token a query sends covers a whole document: the root's token finds the root entry and nothing beneath it. The costs are that the root entry's length reveals the document's size, the row is larger, and the root's direct members are marked by their missing `p`, which puts each top-level field's node count in plain view. Off, there is no document-sized ciphertext, but a read of `$` itself sends the root's token, the whole column's shape.
- **`ordered`** (default none). Each path listed carries an ordering term and takes on the `op` row above; a path not listed cannot be range-queried or sorted, and a query that tries is refused by the client before any key loads. Order only the paths your queries sort or range over.

One disclosure above is a property of the stored format that no option changes today: the depth-first entry order, with members in sorted key order. It is an open decision recorded in the design document (`docs/plans/2026-10-17-json-tree-index.md` at the repository root, Phase 4 notes) and in #1357.

To report a concern with any of this, see `SECURITY.md` at the repository root.
