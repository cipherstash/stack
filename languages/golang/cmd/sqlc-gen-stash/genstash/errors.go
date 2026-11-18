package genstash

import (
	"errors"
	"strings"
)

// Error is a problem in Generate's input: its options, the schema or the
// queries. Err wraps one of the Err sentinels below, which says what the
// problem is, and the other fields say where it is.
type Error struct {
	// Option is the option, as a path in sqlc.yaml: options.stash.identity
	// in a codegen entry, or options.go-stash.go at the top level.
	Option string
	// Column is the table column, table.column, or schema.table.column
	// outside the default schema.
	Column string
	// Query is the query's name.
	Query string
	// Field is a field of a struct sqlc-gen-go declares, Struct.Field.
	Field string
	Err   error
}

func (e *Error) Error() string {
	query := ""
	if e.Query != "" {
		query = "query " + e.Query
	}
	var parts []string
	for _, where := range []string{e.Option, e.Column, query, e.Field} {
		if where != "" {
			parts = append(parts, where)
		}
	}

	return strings.Join(append(parts, e.Err.Error()), ": ")
}

func (e *Error) Unwrap() error {
	return e.Err
}

// Problems with the options.
var (
	// ErrInvalidOption is an option sqlc-gen-go or sqlc-gen-stash doesn't
	// know, or one whose value it can't use.
	ErrInvalidOption = errors.New("invalid option")
	// ErrIncompleteIdentity is a stash.identity without both a pattern and a
	// replacement.
	ErrIncompleteIdentity = errors.New("needs both pattern and replacement")
	// ErrOutInOptions is out in the codegen entry's go options: the entry's
	// own out is the package's folder.
	ErrOutInOptions = errors.New("out is not an option here")
	// ErrUnsupportedSQLPackage is a sql_package sqlc-gen-stash doesn't
	// generate for.
	ErrUnsupportedSQLPackage = errors.New("unsupported sql_package")
	// ErrEQLTypeOverride is an override for an EQL type, whose Go type
	// sqlc-gen-stash gives itself.
	ErrEQLTypeOverride = errors.New("overrides an EQL type")
)

// Problems with the schema and the queries.
var (
	// ErrNoIdentity is an encrypted column stash.identity gives no
	// encryption identity.
	ErrNoIdentity = errors.New("no encryption identity")
	// ErrInvalidIdentity is an encryption identity the SDK would refuse.
	ErrInvalidIdentity = errors.New("invalid encryption identity")
	// ErrInvalidDeclaration is a column the SDK refuses to declare.
	ErrInvalidDeclaration = errors.New("the SDK refuses the column's declaration")
	// ErrSharedIdentity is a column with the encryption identity of another
	// column of its table.
	ErrSharedIdentity = errors.New("shares the encryption identity")
	// ErrQueryTypeColumn is a column whose type is an EQL query type.
	ErrQueryTypeColumn = errors.New("a query type is not a storage type")
	// ErrEQLTypeSchema is a column of an EQL type outside the default
	// schema, where the EQL v4 domains are.
	ErrEQLTypeSchema = errors.New("EQL type outside the default schema")
	// ErrEQLArray is an EQL array column or a sqlc.slice parameter that
	// generated conversions cannot encrypt.
	ErrEQLArray = errors.New("array of an EQL type")
	// ErrUnproducibleType is a column of an EQL type the SDK release can't
	// produce.
	ErrUnproducibleType = errors.New("EQL type this SDK release can't produce")
	// ErrUnknownEQLType is a column of an EQL v4 type the SDK release
	// doesn't know.
	ErrUnknownEQLType = errors.New("EQL type this SDK release doesn't know")
	// ErrViewColumn is an encrypted column of a view.
	ErrViewColumn = errors.New("encrypted column of a view")
	// ErrUnsupportedQueryType is a query parameter cast to an eql_v4 type
	// that isn't the query type of an EQL type the SDK release produces.
	ErrUnsupportedQueryType = errors.New("unsupported query type")
	// ErrUntraceableField is an encrypted field sqlc can't trace to a table
	// column, such as one read through a CTE.
	ErrUntraceableField = errors.New("encrypted field sqlc can't trace to a table column")
	// ErrEncryptedEmbed is a sqlc.embed of a table with encrypted columns
	// beside encrypted fields of the row's own.
	ErrEncryptedEmbed = errors.New("embeds a table with encrypted columns beside encrypted fields")
	// ErrDroppedType is a column whose <Model>Fields value needs a Go type
	// that omit_unused_structs left out of sqlc-gen-go's package.
	ErrDroppedType = errors.New("needs a Go type omit_unused_structs left out")
	// ErrUnsupportedOperator is an operator the SDK's engine answers on a
	// column that sqlc-gen-stash has no query method for.
	ErrUnsupportedOperator = errors.New("unsupported operator")
)
