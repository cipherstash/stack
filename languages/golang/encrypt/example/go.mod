module github.com/cipherstash/stack/languages/golang/encrypt/example

go 1.26.10

// Never released. The SDK and encrypttest at a placeholder version, replaced
// below by the directories in this checkout: the example builds against the
// tree, as an application builds against a released version.
require (
	github.com/cipherstash/stack/languages/golang v0.0.0-00010101000000-000000000000
	github.com/cipherstash/stack/languages/golang/encrypt/encrypttest v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.11.0
)

require (
	github.com/cipherstash/vitaminc/bindings/go/vcffi v0.0.0-20261119095843-f1fc9ae74882 // indirect
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-20261119095843-f1fc9ae74882 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace (
	github.com/cipherstash/stack/languages/golang => ../..
	github.com/cipherstash/stack/languages/golang/encrypt/encrypttest => ../encrypttest
)
