package directory

//go:generate go tool stashgen -type Entry

// Entry stores a name as EQL v4's TextSearch: one column that answers
// =, the orderings and @@, each query carrying only the term its operator
// reads.
type Entry struct {
	_    struct{} `stash:"context=directory"`
	ID   int64    `stash:"id,passthrough" db:"id"`
	Name string   `stash:"name,encrypt_into=TextSearch" db:"name"`
}
