// Package testmember holds a struct the encrypt tests encrypt through the
// two generator paths that take a type the program does not own: the
// `-for` flag (testusers declares the tags for Member in a struct of its
// own) and stashgen.Generate from a policy (genmember writes testpolicy).
// Member has the fields, kinds and indexes of testusers.User, so the three
// paths seal the same declaration and the round-trip tests compare their
// bytes.
package testmember

// Member cannot carry stash tags here: the point is that the tags live
// elsewhere. Its field names are User's so the declarations line up.
type Member struct {
	ID    int64
	Age   uint32
	Email string
	Notes string
}
