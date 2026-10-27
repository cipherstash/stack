module github.com/cipherstash/stack/languages/golang

go 1.26.10

// TEMPORARY: vcffi and vcvalue at vitaminc 06568ba93, the commit on vitaminc
// main that carries the storage profile (vcffi.MarshalStorage, from
// cipherstash/vitaminc#526 by way of cipherstash/vitaminc#544). vitaminc's Go
// bindings have no tags, so the commit is the pin. Only Go writes and reads
// that profile; the guests stay on vitaminc 0.8.0 from crates.io, whose
// transport is the one this commit writes. The pin moves to a tag when
// vitaminc provides one; until then scripts/go-release-version.mjs refuses a
// final version of this module.
require (
	github.com/cipherstash/vitaminc/bindings/go/vcffi v0.0.0-20261026122913-06568ba93bd9
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-20261026122913-06568ba93bd9
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/jackc/pgx/v5 v5.11.0 // test only: encrypt/postgres_test.go, encrypt/eql_postgres_test.go
	golang.org/x/sys v0.49.0
	golang.org/x/tools v0.51.0
	google.golang.org/protobuf v1.36.12
)

require github.com/oapi-codegen/runtime v1.8.0

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/dprotaso/go-yit v0.0.0-20220510233725-9ba8df137936 // indirect
	github.com/getkin/kin-openapi v0.142.0 // indirect
	github.com/go-openapi/jsonpointer v0.23.1 // indirect
	github.com/go-openapi/swag/jsonname v0.26.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/oapi-codegen/oapi-codegen/v2 v2.8.1 // indirect
	github.com/oasdiff/yaml v0.1.1 // indirect
	github.com/oasdiff/yaml3 v0.0.14 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/speakeasy-api/jsonpath v0.6.3 // indirect
	github.com/speakeasy-api/openapi v1.24.0 // indirect
	github.com/vmware-labs/yaml-jsonpath v0.3.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen
