module github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash

go 1.26.10

// The SDK and encrypttest at a placeholder version, replaced below by the
// directories in this checkout, so the plugin builds and tests against the
// tree, as encrypt/example does.
require (
	github.com/cipherstash/stack/languages/golang v0.0.0-00010101000000-000000000000
	github.com/cipherstash/stack/languages/golang/encrypt/encrypttest v0.0.0-00010101000000-000000000000
	github.com/fatih/structtag v1.2.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.12.0
	github.com/jinzhu/inflection v1.0.0
	github.com/sqlc-dev/plugin-sdk-go v1.23.0
	github.com/sqlc-dev/sqlc-gen-go v1.6.1-0.20260420042546-d0bacc9fbaa4 // indirect
	github.com/stretchr/testify v1.12.1
	golang.org/x/mod v0.42.0
)

require (
	github.com/cipherstash/vitaminc/bindings/go/vcffi v0.0.0-20261026122913-06568ba93bd9 // indirect
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-20261026122913-06568ba93bd9 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.84.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// internal/golang is a copy of this version's internal package, made by
// internal/golang/copy.sh. Nothing runs the tool.
tool github.com/sqlc-dev/sqlc-gen-go/plugin

replace (
	github.com/cipherstash/stack/languages/golang => ../..
	github.com/cipherstash/stack/languages/golang/encrypt/encrypttest => ../../encrypt/encrypttest
)
