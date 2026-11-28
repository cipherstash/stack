package sessions

//go:generate go tool stashgen -type Session

// ID is a UUID type that this package declares. Generated code stores a type
// declared as [16]byte as a UUID. The declaration of
// github.com/google/uuid.UUID has the same form.
type ID [16]byte

// Session has four UUID fields:
//
//   - ID has an equality index.
//   - Token is sealed with no index.
//   - Owner may be nil. A nil owner is sealed in the same way as a value, so
//     the stored row does not show that the owner is absent.
//   - Parent may be nil. A nil parent is stored as SQL NULL.
type Session struct {
	_      struct{} `stash:"context=sessions"`
	ID     ID       `stash:"id,encrypt,index=equality"`
	Token  [16]byte `stash:"token,encrypt"`
	Owner  *ID      `stash:"owner,encrypt,index=equality"`
	Parent *ID      `stash:"parent,encrypt,null=sql"`
}
