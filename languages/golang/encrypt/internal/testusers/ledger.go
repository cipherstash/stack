package testusers

import (
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Ledger -name Ledger

// Ledger stores the date, timestamp and numeric EQL v4 types: each family's
// storage-only type and its equality type, from the Go types ADR-0002 maps
// them to (encrypt.Date, time.Time, encrypt.Decimal). Its columns are under
// Profile's table, with names of their own, so its queries sit beside
// v4_queries.json's in v4_ledger_queries.json. It is a model of its own
// because Profile's rows are frozen in stored_v4_rows_v1.json: a new Profile
// field would change what those rows store.
type Ledger struct {
	_       struct{}        `stash:"context=profiles"`
	ID      int64           `stash:"id,passthrough"`
	Opened  encrypt.Date    `stash:"opened,encrypt_into=Date"`
	Due     encrypt.Date    `stash:"due,encrypt_into=DateEq"`
	Created time.Time       `stash:"created,encrypt_into=Timestamp"`
	Posted  time.Time       `stash:"posted,encrypt_into=TimestampEq"`
	Total   encrypt.Decimal `stash:"total,encrypt_into=Numeric"`
	Amount  encrypt.Decimal `stash:"amount,encrypt_into=NumericEq"`
}
