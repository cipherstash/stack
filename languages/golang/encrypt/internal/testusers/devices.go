package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Device -name Device

// DeviceID is a UUID type of the program's own, as
// github.com/google/uuid.UUID is: a type defined over [16]byte.
type DeviceID [16]byte

// Device has a sealed UUID field of each shape stashgen accepts: a type
// defined over [16]byte and [16]byte itself, each with an equality index,
// and a pointer to one with each way of storing nil.
type Device struct {
	_      struct{}  `stash:"context=devices"`
	Name   string    `stash:"name,passthrough"`
	ID     DeviceID  `stash:"id,encrypt,index=equality"`
	Serial [16]byte  `stash:"serial,encrypt,index=equality"`
	Owner  *DeviceID `stash:"owner,encrypt,index=equality"`
	Parent *DeviceID `stash:"parent,encrypt,null=sql"`
}
