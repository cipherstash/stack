// Package individuals declares the tags for pb.Individual, a type with
// unexported fields: the generated file reads each field by name and the
// functions take pointers.
package individuals

import "example.com/app/pb"

//go:generate go tool stashgen -type individualStash -for pb.Individual

type individualStash struct {
	_          struct{} `stash:"context=individuals"`
	Id         int64    `stash:"id,passthrough"`
	Name       string   `stash:"name,encrypt"`
	Email      string   `stash:"email,encrypt,index=equality;match"`
	MedicareNo string   `stash:"medicare_number,encrypt_into=TextEq"`
	Nickname   string   `stash:"nickname,passthrough"`
}

var _ = pb.Individual{}
