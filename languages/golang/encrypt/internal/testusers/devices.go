package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Device -name Device

// DeviceID is a UUID type that this package declares as [16]byte. The type
// github.com/google/uuid.UUID has the same declaration.
type DeviceID [16]byte

// Device has a sealed UUID field of each form that stashgen accepts:
//
//   - ID is a type declared as [16]byte, with an equality index.
//   - Serial is [16]byte itself, with an equality index.
//   - Owner is a pointer that stores nil as a sealed null. A sealed null is
//     nil encrypted in the same way as a value.
//   - Parent is a pointer that stores nil as SQL NULL.
type Device struct {
	_      struct{}  `stash:"context=devices"`
	Name   string    `stash:"name,passthrough"`
	ID     DeviceID  `stash:"id,encrypt,index=equality"`
	Serial [16]byte  `stash:"serial,encrypt,index=equality"`
	Owner  *DeviceID `stash:"owner,encrypt,index=equality"`
	Parent *DeviceID `stash:"parent,encrypt,null=sql"`
}
