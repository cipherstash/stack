package testusers

import "github.com/cipherstash/stack/languages/golang/encrypt"

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Person -name Person
//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Birthday -name Birthday

// Person has optional fields, each declared over a pointer, in both ways a
// field stores nil (#1298). DOB, Born and Age store it as a sealed null, as
// long as a value, which the generator picks for a type of fixed width whose
// only index is equality: Born's and Age's equality terms of nil are the one
// term every nil shares, which EqNull queries. Joined, Score and Nick store
// SQL NULL, which an order index and text have to ask for.
type Person struct {
	_      struct{}      `stash:"context=people"`
	ID     int64         `stash:"id,passthrough"`
	DOB    *encrypt.Date `stash:"dob,encrypt_into=Date"`
	Born   *encrypt.Date `stash:"born,encrypt_into=DateEq"`
	Joined *encrypt.Date `stash:"joined,encrypt_into=DateEq,null=sql"`
	Age    *int32        `stash:"age,encrypt,index=equality"`
	Score  *int64        `stash:"score,encrypt,index=ore,null=sql"`
	Nick   *string       `stash:"nick,encrypt,null=sql"`
}

// Birthday reads Person's dob column into a field that is not a pointer,
// so a stored null has nowhere to go.
type Birthday struct {
	_   struct{}     `stash:"context=people"`
	DOB encrypt.Date `stash:"dob,encrypt_into=Date"`
}
