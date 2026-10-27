# Administer a workspace

`control` manages CipherStash Token Service (CTS) actors and memberships, and ZeroKMS keysets, clients and grants.
It uses the same [`auth`](../auth/README.md) strategies as encryption. Management does not require an encryption client key.

## Authenticate and list clients

Create an access key with the permissions your operations need. Use an Admin key for actor and client administration.
Set `CS_WORKSPACE_CRN` and `CS_ADMIN_ACCESS_KEY`, then run this program:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/control"
)

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := auth.OpenWithoutProfile(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	crn := os.Getenv("CS_WORKSPACE_CRN")
	strategy, err := store.AccessKey(
		ctx,
		crn,
		auth.NewAccessKey([]byte(os.Getenv("CS_ADMIN_ACCESS_KEY"))),
	)
	if err != nil {
		return err
	}
	defer strategy.Close()

	client, err := control.NewClient(
		ctx,
		crn,
		control.WithCTSAuth(strategy),
		control.WithZeroKMSAuth(strategy),
	)
	if err != nil {
		return err
	}

	clients, err := client.ListClients(ctx, control.ListClientsOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("%d clients\n", len(clients))
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
```

Build the credential guest with `mise run wasm:auth-guest:build` when using a source checkout.
Released Go module tags include it. An ordinary commit does not.

Configure only `WithZeroKMSAuth` for a worker that needs no CTS administration.
Separate strategies can authenticate the two services. The server authorizes each operation;
successful SDK construction does not prove permission to perform an operation.

The client borrows strategies and transports. Keep their credential stores open until requests finish; there is no `control.Client.Close`.
Each operation calls `strategy.ServiceToken(ctx)` and uses the bearer and decoded endpoint from that same snapshot, checking the workspace and requiring an HTTPS origin.
This follows stack-auth's existing client contract: no local JWT signature verification, and no additional token cache or discovery/JWKS requests.
Trust the strategy's CTS configuration and credential store; decoded metadata is not proof of token authenticity.

## Manage resources and creation secrets

- Actors: `CreateActor`, `ListActors`, `DeleteActor`, plus `ListAccessKeys` for key metadata.
- Encryption clients: `CreateClient`, `ListClients`, `DeleteClient`. This resource is named `EncryptionClient`, distinct from the administrative `Client`.
- Keysets: `CreateKeyset`, `ListKeysets`, `ModifyKeyset`, `EnableKeyset`, `DisableKeyset`, `GrantKeyset`, `RevokeKeyset`.
- Memberships: `CreateMembership`, `ListMemberships`, `DeleteMembership`.

`ListActors` returns one page. Pass its `NextCursor` to the next call until empty.
Keyset and client lists are not paginated. `ShowDisabled` includes disabled keysets; `ListClientsOptions.KeysetID` filters by a keyset UUID.
Unfiltered clients retain every associated keyset ID. A client may have no grants.
Null or malformed inventories return `ErrResponse`; they do not mean every resource was deleted.

`CreateClient` defaults to the workspace's default keyset when `KeysetID` is empty. Explicit keyset identifiers are UUIDs.
`CreateKeyset` can create an optional client. Its `ClientType` is `"device"`, the service's supported value.
There is no keyset deletion operation. Disabling a keyset is not deletion.
Creating a membership returns no role; read it using `ListMemberships`.

Creation returns secret material only once. Choose one transfer:

- `CreatedActor.TakeAccessKey()` returns an owned `*auth.AccessKey` for `ProfileStore.AccessKey`.
- `CreatedClient.TakeClientKey()` returns an owned `*auth.ClientKey` for encryption credentials.
- `ExportAccessKey()` or `ExportClientKey()` returns owned bytes for persistence. Client-key bytes stay base64-encoded.

Copies share the same extraction right. A second extraction returns `ErrSecretConsumed`.
Call `Wipe()` on unused creation results, including the optional client returned with a keyset. Wipe exported bytes after persistence.
Formatting redacts creation results, and JSON serialization omits secret material.
These controls cannot erase immutable environment strings, caller-created copies, vault records or Terraform state.

Deleting an actor removes its key metadata, but must not be treated as immediate token revocation.
Already issued tokens may remain usable, and fresh exchanges sometimes succeed immediately after deletion.

## Handle errors without retrying unknown writes

Use `errors.Is` for `ErrAuthentication`, `ErrForbidden`, `ErrNotFound`, `ErrConflict`, `ErrTransport` and `ErrResponse`.
Use `errors.As` with `*HTTPError` for the service and exact status, including HTTP 400.
Errors exclude response bodies because those bodies may contain credentials.

The SDK does not retry administrative writes or follow redirects. A transport failure or an incomplete creation response (`ErrResponse`) can follow a successful server-side mutation.
Reconcile inventory before deciding to repeat a create operation. Tenant naming and retry policy belong to the application.
Requests use an SDK User-Agent, a 30-second operation timeout including authentication, and an 8 MiB response limit.
Pass a shorter context deadline when needed.

## Verification limits

The public-interface tests run the real credential guest against unsigned token fixtures and TLS test servers.
Live Development probes exercised actor/client create, list and delete, and creation-secret transfer.
Admin and Control grant/revoke requests against the existing default keyset returned HTTP 500; success is not established by those probes.
A synthetic membership subject was rejected with HTTP 422. Real-user membership creation and deletion remain unproven.
Keyset creation and enable/disable were not exercised against shared data because keysets cannot be deleted.
Live OIDC federation requires a registered external identity provider; fixture coverage is not a live-provider proof.

## Maintain the generated service protocol

`internal/cts` and `internal/zerokms` contain checked-in OpenAPI snapshots, generator configurations, overlays and generated Go code.
The snapshots were downloaded on 2026-10-27 from these public service endpoints:

| Snapshot | Source |
| --- | --- |
| `internal/cts/openapi.json` | <https://eu-central-1.aws.cts.cipherstashmanaged.net/api/openapi.json> |
| `internal/zerokms/openapi.json` | <https://ap-southeast-2.aws.zerokms.cipherstashmanaged.net/api/openapi.json> |

`go.mod` pins oapi-codegen v2.8.1 as a Go tool and its runtime at v1.8.0.
From `languages/golang`, regenerate with:

```sh
go generate ./control/internal/...
go test ./control/...
golangci-lint run ./...
```

Generation reads only the checked-in snapshots; remote schema references are disabled.
The existing Go CI job runs `go generate ./...` and rejects changed or untracked output.
To update a snapshot, download its source, format it with `jq .`, inspect the schema changes, and regenerate.
Keep generator adaptations in the overlays, not in the upstream schema or generated Go files.

The configurations select only the SDK's administrative operations.
CTS's overlay gives those operations unique names and preserves the SDK's integer widths.
Both configurations represent UUIDs as strings, leaving identifier validation to the service as before.
ZeroKMS's overlay preserves missing/null checks for required scalar fields and keeps creation keys base64-encoded.
The CTS creation-response decoder also retains the optional `createdAt` field, which its published schema does not describe.

Only request builders and wire models are used from the generated packages.
The public types, authentication, deadlines, response limit, error mapping and secret ownership remain in `control`.
Do not replace its decoder with generated `WithResponse` methods: those read unbounded bodies and retain raw responses.
Generated types do not validate required fields or provide the Rust secret-handling guarantees mentioned in copied schema descriptions.
The SDK's explicit response checks and one-shot secret wrappers remain necessary.
