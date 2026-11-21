module github.com/cipherstash/stack/languages/golang

go 1.26.10

// TEMPORARY: vcffi and vcvalue at vitaminc f1fc9ae74, the commit vitaminc
// 0.10.0 was released from, so the host checks dates and timestamps against
// the range the guests' vitaminc 0.10.0 does (years -9999 to 9999), and
// writes the storage profile (vcffi.MarshalStorage) and the transport the
// guests read. vitaminc's Go bindings have no tags, so the commit is the pin.
// The pin moves to a tag when vitaminc provides one; until then
// scripts/go-release-version.mjs refuses a final version of this module.
require (
	github.com/cipherstash/vitaminc/bindings/go/vcffi v0.0.0-20261119095843-f1fc9ae74882
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-20261119095843-f1fc9ae74882
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/jackc/pgx/v5 v5.11.0 // test only: encrypt/postgres_test.go, encrypt/eql_postgres_test.go
	golang.org/x/sys v0.49.0
	golang.org/x/tools v0.52.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)
