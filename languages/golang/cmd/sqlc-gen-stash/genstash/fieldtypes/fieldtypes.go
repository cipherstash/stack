// sqlc-gen-stash writes this file, with its package clause changed,
// beside the stash.go of every package it writes field helpers for. The
// <Model>Fields values there name a Column for each plaintext column, and
// one of the encrypted field types below for each encrypted column: the
// one whose methods are the operators the SDK's engine answers on it.
//
// No encrypted field type has a Zero method, nor does anything they embed.
// A query builder that infers a plaintext column's Go type from Zero would
// otherwise accept an encrypted column, and compare and sort its ciphertext
// as if it were plaintext.

package fieldtypes

import (
	"context"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
)

// Column is a plaintext column: its table, its name and T, the Go type
// sqlc-gen-go gives it.
type Column[T any] struct {
	table, column string
}

// Table is the column's table, without its schema.
func (c Column[T]) Table() string {
	return c.table
}

// Column is the column's name.
func (c Column[T]) Column() string {
	return c.column
}

// QualifiedName is table.column.
func (c Column[T]) QualifiedName() string {
	return c.table + "." + c.column
}

// Zero is T's zero value. It puts T in the method set, so a generic
// function can infer T from a Column.
func (Column[T]) Zero() T {
	var zero T

	return zero
}

// encrypted is what every encrypted field type holds and the methods they
// share. P is the column's plaintext Go type, and E its EQL type in
// encrypt/eql.
type encrypted[P any, E ~[]byte] struct {
	table, column, eqlType string
	null                   gensupport.NullMode
	field                  gensupport.Field[P]
}

// newField is the value of the encrypted column of d named column, as the
// encrypted field type F.
func newField[F ~struct{ encrypted[P, E] }, P any, E ~[]byte](d gensupport.Declaration, table, column, eqlType string, null gensupport.NullMode) F {
	return F{encrypted[P, E]{table, column, eqlType, null, gensupport.NewField[P](d, column)}}
}

// Table is the column's table, without its schema.
func (f encrypted[P, E]) Table() string {
	return f.table
}

// Column is the column's name.
func (f encrypted[P, E]) Column() string {
	return f.column
}

// QualifiedName is table.column.
func (f encrypted[P, E]) QualifiedName() string {
	return f.table + "." + f.column
}

// EQLType is the column's EQL type, which says that it is encrypted.
func (f encrypted[P, E]) EQLType() string {
	return f.eqlType
}

// NullMode is how the column stores nil: SQL NULL, or "" when it can't be
// NULL.
func (f encrypted[P, E]) NullMode() gensupport.NullMode {
	return f.null
}

// Encrypt seals one value for the column.
func (f encrypted[P, E]) Encrypt(ctx context.Context, c *encrypt.Cipher, v P) (E, error) {
	out, err := f.field.Encrypt(ctx, c, v)

	return E(out.EQL), err
}

// term derives the query of operator for v, as the query type Q.
func term[Q ~[]byte, P any, E ~[]byte](ctx context.Context, f encrypted[P, E], c *encrypt.Cipher, operator string, v P) (Q, error) {
	t, err := f.field.Term(ctx, c, operator, v)

	return Q(t), err
}

// matches derives the matches query for v.
func matches[Q ~[]byte, P ~string, E ~[]byte](ctx context.Context, f encrypted[P, E], c *encrypt.Cipher, v P) (encrypt.EQLMatchQuery[Q, P], error) {
	return gensupport.EQLMatches[Q](ctx, f.field, c, v)
}

// Stored is an encrypted column the engine answers no operator on.
type Stored[P any, E ~[]byte] struct{ encrypted[P, E] }

// Eq is an encrypted column the engine answers eq on. Q is its EQL query
// type.
type Eq[P any, E, Q ~[]byte] struct{ encrypted[P, E] }

// Eq derives the eq query for v.
func (f Eq[P, E, Q]) Eq(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "eq", v)
}

// Ord is an encrypted column the engine answers lt, lte, gt and gte on. Q
// is its EQL query type.
type Ord[P any, E, Q ~[]byte] struct{ encrypted[P, E] }

// Lt derives the lt query for v.
func (f Ord[P, E, Q]) Lt(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "lt", v)
}

// Lte derives the lte query for v.
func (f Ord[P, E, Q]) Lte(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "lte", v)
}

// Gt derives the gt query for v.
func (f Ord[P, E, Q]) Gt(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "gt", v)
}

// Gte derives the gte query for v.
func (f Ord[P, E, Q]) Gte(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "gte", v)
}

// Match is an encrypted column the engine answers matches on. Q is its EQL
// query type.
type Match[P ~string, E, Q ~[]byte] struct{ encrypted[P, E] }

// Matches derives the matches query for v. Its answer can hold rows that do
// not match: decrypt the rows it fetches and keep those Verify reports true.
func (f Match[P, E, Q]) Matches(ctx context.Context, c *encrypt.Cipher, v P) (encrypt.EQLMatchQuery[Q, P], error) {
	return matches[Q](ctx, f.encrypted, c, v)
}

// EqOrd is an encrypted column the engine answers eq, lt, lte, gt and gte
// on. Q is its EQL query type.
type EqOrd[P any, E, Q ~[]byte] struct{ encrypted[P, E] }

// Eq derives the eq query for v.
func (f EqOrd[P, E, Q]) Eq(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "eq", v)
}

// Lt derives the lt query for v.
func (f EqOrd[P, E, Q]) Lt(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "lt", v)
}

// Lte derives the lte query for v.
func (f EqOrd[P, E, Q]) Lte(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "lte", v)
}

// Gt derives the gt query for v.
func (f EqOrd[P, E, Q]) Gt(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "gt", v)
}

// Gte derives the gte query for v.
func (f EqOrd[P, E, Q]) Gte(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "gte", v)
}

// Search is an encrypted column the engine answers eq, lt, lte, gt, gte
// and matches on. Q is its EQL query type.
type Search[P ~string, E, Q ~[]byte] struct{ encrypted[P, E] }

// Eq derives the eq query for v.
func (f Search[P, E, Q]) Eq(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "eq", v)
}

// Lt derives the lt query for v.
func (f Search[P, E, Q]) Lt(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "lt", v)
}

// Lte derives the lte query for v.
func (f Search[P, E, Q]) Lte(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "lte", v)
}

// Gt derives the gt query for v.
func (f Search[P, E, Q]) Gt(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "gt", v)
}

// Gte derives the gte query for v.
func (f Search[P, E, Q]) Gte(ctx context.Context, c *encrypt.Cipher, v P) (Q, error) {
	return term[Q](ctx, f.encrypted, c, "gte", v)
}

// Matches derives the matches query for v. Its answer can hold rows that do
// not match: decrypt the rows it fetches and keep those Verify reports true.
func (f Search[P, E, Q]) Matches(ctx context.Context, c *encrypt.Cipher, v P) (encrypt.EQLMatchQuery[Q, P], error) {
	return matches[Q](ctx, f.encrypted, c, v)
}

// Document is an encrypted JSON document column with no ordered paths,
// which the engine answers contains, contained_by, eq_at, selector,
// subtree, children, child_count and match on. Q is its EQL query type,
// Entry the type of an encrypted entry it reads, and Predicate the type of
// a jsonpath predicate's operand.
type Document[P any, E, Q, Entry, Predicate ~[]byte] struct{ encrypted[P, E] }

// Contains derives the query for documents that contain needle: col @> query.
// needle is a json.RawMessage of JSON text, or a map, struct or slice that
// encoding/json writes; a Go string or a pointer to one is refused, as one JSON
// string is not JSON text, and so is a needle that writes JSON null (nil, or a
// nil pointer, map or slice). Each member it writes must be in the document, so
// a zero-valued struct field narrows the query to documents holding that zero:
// give a needle struct pointer fields, or omitempty, or use a map. Each array
// element of the needle must sit inside one element of the document's array.
func (f Document[P, E, Q, Entry, Predicate]) Contains(ctx context.Context, c *encrypt.Cipher, needle any) (Q, error) {
	return gensupport.JSONQuery[Q](ctx, f.field, c, "contains", needle)
}

// ContainedBy derives the query for documents contained by needle: col <@
// query. needle is a json.RawMessage of JSON text, or a map, struct or slice
// that encoding/json writes (not a Go string or a pointer to one, nor a needle
// that writes JSON null); here a zero-valued field widens the query, admitting
// documents that hold that zero.
func (f Document[P, E, Q, Entry, Predicate]) ContainedBy(ctx context.Context, c *encrypt.Cipher, needle any) (Q, error) {
	return gensupport.JSONQuery[Q](ctx, f.field, c, "contained_by", needle)
}

// EqAt derives the query for documents holding the scalar v at path: col @>
// query. v is a Go string, number or bool, nil for JSON null, or a
// json.RawMessage of JSON text; a Go string is the JSON string it holds, never
// parsed as JSON. A wildcard step matches when any element holds it; a position
// ([2]) is refused, since the stored selector reads every position as the
// wildcard.
func (f Document[P, E, Q, Entry, Predicate]) EqAt(ctx context.Context, c *encrypt.Cipher, path string, v any) (Q, error) {
	return gensupport.JSONQueryAt[Q](ctx, f.field, c, "eq_at", path, v)
}

// Selector prepares `->` at path: bind Selector() as col -> $1::text, and open
// the entries it returns with Open; encrypt.DecodeJSON reads each value into a
// Go type. A position ([2]) is refused; read one with Subtree.
func (f Document[P, E, Q, Entry, Predicate]) Selector(ctx context.Context, c *encrypt.Cipher, path string) (encrypt.JSONSelection[Entry], error) {
	return gensupport.JSONSelect[Entry](ctx, f.field, c, path)
}

// Subtree prepares a read of the value at path: bind Tokens() as
// eql_v4.json_tree_subtree(col, $1::text[], budget), and open the rows it
// returns with Open or OpenOne; encrypt.DecodeJSON reads each value into a Go
// type.
func (f Document[P, E, Q, Entry, Predicate]) Subtree(ctx context.Context, c *encrypt.Cipher, path string, opts encrypt.JSONReadOptions) (encrypt.JSONRead[Entry], error) {
	return gensupport.JSONSubtree[Entry](ctx, f.field, c, path, opts)
}

// Children derives the token of the node at path, a path with no wildcard,
// which eql_v4.json_tree_children(col, $1::text) takes. Its rows are encrypted
// entries one level down.
func (f Document[P, E, Q, Entry, Predicate]) Children(ctx context.Context, c *encrypt.Cipher, path string) (encrypt.JSONToken, error) {
	return gensupport.JSONNodeToken(ctx, f.field, c, "children", path)
}

// ChildCount derives the token of the node at path, which
// eql_v4.json_tree_child_count(col, $1::text) takes: zero for a scalar or an
// empty container, NULL where the row has no node there or for the sealed root.
func (f Document[P, E, Q, Entry, Predicate]) ChildCount(ctx context.Context, c *encrypt.Cipher, path string) (encrypt.JSONToken, error) {
	return gensupport.JSONNodeToken(ctx, f.field, c, "child_count", path)
}

// Match derives the operand for a jsonpath predicate over the document, as
// plaintext jsonb_path_match(col, predicate, vars) takes one: bind it as col @@
// $1::eql_v4.query_json_predicate, or eql_v4.json_tree_match(col,
// $1::eql_v4.query_json_predicate). vars are the predicate's variables ($name):
// a map, a struct or a json.RawMessage that writes a JSON object, and an empty
// map when there are none. A nil vars is SQL NULL, as pgx and database/sql bind
// it over plaintext: the operand is empty, binds as NULL, and matches no row,
// as jsonb_path_match does with NULL vars.
//
// The engine reads the predicate, and nothing in Go does: paths of .key,
// ."quoted key" and [*] steps; ==, !=, <, <=, > and >= between a path and a
// variable or a JSON literal; exists(path), and exists(path ? (@.m == $v && @.n
// > $w)) for several members of one array element; &&, || and !(…). Anything
// else is refused, before any term is derived, as an *encrypt.Diagnostic
// wrapping encrypt.ErrEncoding whose Reason, Construct and At name the refusal
// and the byte offset in predicate where it starts. The column orders no path,
// so an ordering, or a filter of more than one condition, is refused wrapping
// encrypt.ErrTerm.
//
// The tree is evaluated inside eql_v4.json_tree_match, which engages no index:
// every row the scan gives it is opened and tested. Contains and EqAt engage
// the GIN index for @>, so a query that needs an index writes those leaves with
// them, or narrows the rows with one beside Match.
//
// A query returns jsonb_path_match's rows over the plaintext, and each row
// answers as it does, true, false or NULL, save these cases. Lax mode's
// unwrapping of an array the path names no [*] for is not applied: write [*].
// Nor is its wrapping of a value that is not an array under [*]. A string
// compared with a number is false under == and true under !=, where jsonpath
// says unknown.
func (f Document[P, E, Q, Entry, Predicate]) Match(ctx context.Context, c *encrypt.Cipher, predicate string, vars any, opts encrypt.JSONReadOptions) (Predicate, error) {
	return gensupport.JSONMatch[Predicate](ctx, f.field, c, predicate, vars, opts)
}
