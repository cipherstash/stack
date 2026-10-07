// Package orders holds two tagged structs. Order carries -name, so the
// package has one Encrypt (for Refund) and one EncryptOrder.
package orders

//go:generate go tool stashgen -type Order -name Order
//go:generate go tool stashgen -type Refund

// Order uses separate columns: an ordered amount, and a note with no index.
type Order struct {
	_        struct{} `stash:"context=orders"`
	ID       int64    `stash:"id,passthrough" db:"id"`
	Amount   int64    `stash:"amount,encrypt,index=equality;ore" db:"amount"`
	Note     string   `stash:"note,encrypt"`
	Customer string   `stash:"customer,encrypt,index=match;ope"`
}

// Refund has String and LogValue, so stashgen does not warn about printing.
type Refund struct {
	_      struct{} `stash:"context=refunds"`
	ID     int64    `stash:"id,passthrough"`
	Reason string   `stash:"reason,encrypt_into=TextEq"`
}

func (Refund) String() string { return "Refund{...}" }

func (Refund) LogValue() any { return nil }
