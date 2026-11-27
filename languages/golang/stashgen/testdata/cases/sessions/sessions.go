package sessions

//go:generate go tool stashgen -type Session

// ID is a UUID type of the program's own. Any type defined over [16]byte,
// such as github.com/google/uuid.UUID, is stored as a UUID.
type ID [16]byte

// Session stores UUIDs: one queried by equality, one sealed with no index,
// and two that may be nil. A nil owner is sealed like a value, so the
// stored row does not show that it is absent; a nil parent is SQL NULL.
type Session struct {
	_      struct{} `stash:"context=sessions"`
	ID     ID       `stash:"id,encrypt,index=equality"`
	Token  [16]byte `stash:"token,encrypt"`
	Owner  *ID      `stash:"owner,encrypt,index=equality"`
	Parent *ID      `stash:"parent,encrypt,null=sql"`
}
