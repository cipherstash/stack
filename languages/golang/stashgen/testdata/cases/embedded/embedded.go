// Package embedded shows an embedded struct of the same package: its tagged
// fields join the outer struct.
package embedded

//go:generate go tool stashgen -type Patient

type Person struct {
	Name  string `stash:"name,encrypt_into=TextEq" json:"name"`
	Email string `stash:"email,encrypt,index=equality" json:"email"`
	notes string
}

type Patient struct {
	_ struct{} `stash:"context=patients"`
	Person
	MRN   string `stash:"mrn,passthrough" json:"mrn"`
	Chart []byte `stash:"chart,encrypt"`
}
