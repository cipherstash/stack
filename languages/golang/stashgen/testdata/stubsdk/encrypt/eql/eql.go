// Package eql is a TEST STUB of the generated EQL types: the types the
// golden cases name, and their query types.
package eql

// TextEq is an EQL value with an equality term.
type TextEq []byte

// TextEqQuery is the query value for TextEq.
type TextEqQuery []byte

// TextMatch is an EQL value with a match term.
type TextMatch []byte

// TextMatchQuery is the query value for TextMatch.
type TextMatchQuery []byte

// TextSearch is an EQL value with equality, order and match terms.
type TextSearch []byte

// TextSearchQuery is the query value for TextSearch.
type TextSearchQuery []byte

// JSONSearch is an encrypted JSON document.
type JSONSearch []byte

// JSONSearchQuery is the query value for JSONSearch.
type JSONSearchQuery []byte

// JSONSearchLeafQuery is an ordering's operand at a path of a JSONSearch.
type JSONSearchLeafQuery []byte

// JSONSearchElementsQuery is the element match's operand on a JSONSearch.
type JSONSearchElementsQuery []byte

// JSONSearchPredicateQuery is a compiled jsonpath predicate's operand on a
// JSONSearch.
type JSONSearchPredicateQuery []byte

// JSONEntry is one encrypted entry of a JSONSearch document.
type JSONEntry []byte
