package testusers

import (
	"database/sql"
	"time"
)

// Defined types over scalars: the engine returns the underlying type and the
// generated code converts.
type (
	Email string
	Blob  []byte
	Score int16
)

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Account -name Account

// Account is the shape of the plan's accounts example: passthrough fields
// whose types the FFI codec cannot carry (a time.Time, a driver.Valuer), kept
// on the host and returned as they are.
type Account struct {
	_         struct{}     `stash:"context=accounts"`
	ID        uint         `stash:"id,passthrough"`
	CreatedAt time.Time    `stash:"created_at,passthrough"`
	DeletedAt sql.NullTime `stash:"deleted_at,passthrough"`
	Email     string       `stash:"email,encrypt,index=equality"`
}

// Inner is a struct carried through a passthrough field and inside an
// opaque struct.
type Inner struct {
	Name string
	N    int32
}

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Kinds -name Kinds

// Kinds has one sealed field of every scalar kind stashgen accepts outside
// an opaque struct, with defined types among them, and passthrough fields of
// types the codec cannot carry. Everything it accepts round-trips.
type Kinds struct {
	_   struct{} `stash:"context=kinds"`
	S   string   `stash:"s,encrypt,index=equality;match"`
	E   Email    `stash:"e,encrypt,index=equality;match;ore"`
	Bo  bool     `stash:"bo,encrypt"`
	I8  int8     `stash:"i8,encrypt,index=equality;ore"`
	I16 int16    `stash:"i16,encrypt,index=ope"`
	I32 int32    `stash:"i32,encrypt,index=equality"`
	I   int      `stash:"i,encrypt,index=ore"`
	I64 int64    `stash:"i64,encrypt"`
	U8  uint8    `stash:"u8,encrypt,index=equality"`
	U16 uint16   `stash:"u16,encrypt"`
	U32 uint32   `stash:"u32,encrypt,index=equality;ore"`
	U   uint     `stash:"u,encrypt"`
	U64 uint64   `stash:"u64,encrypt,index=ope"`
	F32 float32  `stash:"f32,encrypt"`
	F64 float64  `stash:"f64,encrypt,index=ore"`
	By  []byte   `stash:"by,encrypt,index=equality"`
	Bl  Blob     `stash:"bl,encrypt"`
	Sc  Score    `stash:"sc,encrypt,index=ore"`

	P  *int              `stash:"p,passthrough"`
	M  map[string]string `stash:"m,passthrough"`
	T  time.Time         `stash:"t,passthrough"`
	N  sql.NullTime      `stash:"n,passthrough"`
	In Inner             `stash:"in,passthrough"`
	Sk []Inner           `stash:"sk,passthrough"`
}

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Everything -name Everything

// Everything is an opaque struct with a field of every type JSON carries
// both ways. It crosses as one document and comes back as it was.
type Everything struct {
	_      struct{} `stash:"context=everything,opaque"`
	S      string
	E      Email
	Bo     bool
	I8     int8
	I      int
	U64    uint64
	F32    float32
	F64    float64
	By     []byte
	Bl     Blob
	Sc     Score
	Tags   []string
	Emails []Email
	Counts map[string]int
	Labels map[string]string
	ByKey  map[int]string
	In     Inner
	Ins    []Inner
	P      *string
	PI     *Inner
	T      time.Time
	N      sql.NullTime
	Nested [][]byte
	Arr    [2]uint8
}
