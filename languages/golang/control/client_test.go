package control_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/control"
)

const workspace = "ZVATKW3VHMFG27DY"
const crn = "crn:ap-southeast-2.aws:" + workspace

func serviceJWT(t *testing.T, issuer, subject, zerokms string) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{
		"iss": issuer + "/", "sub": subject, "workspace": workspace,
		"services": map[string]string{"zerokms": zerokms + "/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))

	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + "."
}

// Exercise the public client through real guest acquisition and TLS HTTP.
// Distinct tokens catch accidentally using CTS credentials for ZeroKMS.
func authenticatedClient(t *testing.T, handler http.HandlerFunc) *control.Client {
	t.Helper()
	tokens := map[string]string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/authorise":
			var input struct {
				AccessKey string `json:"accessKey"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": tokens[input.AccessKey], "expiry": time.Now().Add(time.Hour).Unix()})
		default:
			credential := "CSAKkms.secret"
			if strings.HasPrefix(r.URL.Path, "/api/") {
				credential = "CSAKcts.secret"
				if r.Header.Get("x-cs-workspace-id") != workspace {
					t.Error("CTS workspace header missing")
				}
			}

			if r.Header.Get("Authorization") != "Bearer "+tokens[credential] {
				t.Error("wrong service credential")
			}

			handler(w, r)
		}
	}))
	t.Cleanup(server.Close)
	for _, credential := range []string{"CSAKcts.secret", "CSAKkms.secret"} {
		tokens[credential] = serviceJWT(t, server.URL, credential, server.URL)
	}

	ctx := context.Background()
	store, err := auth.OpenWithoutProfile(ctx, auth.WithRoundTripper(server.Client().Transport))
	if errors.Is(err, auth.ErrGuestNotBuilt) {
		t.Skip(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = store.Close() })
	strategies := make([]*auth.Strategy, 0, 2)
	for _, credential := range []string{"CSAKcts.secret", "CSAKkms.secret"} {
		strategy, err := store.AccessKey(ctx, crn, auth.NewAccessKey([]byte(credential)), auth.WithBaseURL(server.URL))
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = strategy.Close() })
		strategies = append(strategies, strategy)
	}

	if _, err := control.NewClient(ctx, "crn:ap-southeast-2.aws:2JTSJCX24VP2WCBC", control.WithCTSAuth(strategies[0])); !errors.Is(err, control.ErrAuthentication) {
		t.Fatalf("cross-workspace client accepted: %v", err)
	}

	if _, err := control.NewClient(ctx, "crn:us-east-1.aws:"+workspace, control.WithCTSAuth(strategies[0])); !errors.Is(err, control.ErrAuthentication) {
		t.Fatalf("cross-region client accepted: %v", err)
	}

	client, err := control.NewClient(ctx, crn, control.WithCTSAuth(strategies[0]), control.WithZeroKMSAuth(strategies[1]), control.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func TestActorClientContractsAndOneShotSecrets(t *testing.T) {
	client := authenticatedClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/actors":
			if r.Method == http.MethodPost {
				var input control.CreateActorOptions
				_ = json.NewDecoder(r.Body).Decode(&input)
				if input.Name != "worker" || input.Kind != "app" || input.Role != "control" {
					t.Error("actor request differs")
				}

				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, `{"actorId":"actor-1","name":"worker","kind":"app","createdAt":"today","role":"control","accessKey":"CSAKone.secret"}`)
			} else {
				if r.URL.Query().Get("cursor") != "a+/=" || r.URL.Query().Get("limit") != "7" {
					t.Error("pagination changed")
				}

				fmt.Fprint(w, `{"items":[{"actorId":"actor-1","name":"worker","kind":"app"}],"nextCursor":"second"}`)
			}
		case "/api/access-keys":
			fmt.Fprint(w, `[{"keyId":"key-1","keyName":"worker","workspaceId":"ZVATKW3VHMFG27DY","role":"control","createdAt":"today","lastUsedAt":null}]`)
		case "/create-client":
			var input map[string]any
			_ = json.NewDecoder(r.Body).Decode(&input)
			if !reflect.DeepEqual(input, map[string]any{"name": "app", "description": "test", "keyset_id": "keyset-1"}) {
				t.Error("create client request differs")
			}

			fmt.Fprint(w, `{"id":"client-1","name":"app","description":"test","dataset_id":"keyset-1","client_key":"encoded-client-key"}`)
		case "/list-clients":
			var input map[string]any
			_ = json.NewDecoder(r.Body).Decode(&input)
			if !reflect.DeepEqual(input, map[string]any{"keyset_id": map[string]any{"Uuid": "keyset-1"}}) {
				t.Error("client filter differs")
			}

			fmt.Fprint(w, `[{"id":"one","name":"single","keyset_id":"keyset-1"},{"id":"two","name":"multiple","keyset_id":["keyset-2","keyset-1"]}]`)
		case "/api/actors/actor-1":
			if r.Method != http.MethodDelete {
				t.Error("actor delete method")
			}

			fmt.Fprint(w, `{}`)
		case "/delete-client":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			if r.Method != http.MethodPost || input["client_id"] != "client-1" {
				t.Error("client delete request")
			}

			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected operation %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	actor, err := client.CreateActor(ctx, control.CreateActorOptions{Name: "worker", Kind: "app", Role: "control"})
	if err != nil {
		t.Fatal(err)
	}

	if actor.ID != "actor-1" || actor.CreatedAt != "today" || actor.Role != "control" {
		t.Fatal("actor metadata lost")
	}

	copyActor := *actor
	key, err := actor.TakeAccessKey()
	if err != nil || key.IsZero() {
		t.Fatal("typed secret transfer failed")
	}

	key.Wipe()
	if _, err := copyActor.ExportAccessKey(); !errors.Is(err, control.ErrSecretConsumed) {
		t.Fatal("copied result exported secret twice")
	}

	page, err := client.ListActors(ctx, control.ListActorsOptions{Limit: 7, Cursor: "a+/="})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "actor-1" || page.NextCursor != "second" {
		t.Fatalf("actor page: %v", err)
	}

	keys, err := client.ListAccessKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].ID != "key-1" || keys[0].LastUsedAt != nil {
		t.Fatalf("key metadata: %v", err)
	}

	created, err := client.CreateClient(ctx, control.CreateClientOptions{Name: "app", Description: "test", KeysetID: "keyset-1"})
	if err != nil {
		t.Fatal(err)
	}

	if created.ID != "client-1" || created.KeysetID != "keyset-1" {
		t.Fatal("client metadata lost")
	}

	encoded, _ := json.Marshal(created)
	if strings.Contains(string(encoded), "encoded-client-key") || strings.Contains(fmt.Sprintf("%#v", created), "encoded-client-key") {
		t.Fatal("secret leaked")
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			copyClient := *created
			b, err := copyClient.ExportClientKey()
			if err == nil {
				wins.Add(1)
				if string(b) != "encoded-client-key" {
					t.Error("encoded secret changed")
				}

				clear(b)
			} else if !errors.Is(err, control.ErrSecretConsumed) {
				t.Error(err)
			}
		})
	}

	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("secret transfer was not exclusive")
	}

	listed, err := client.ListClients(ctx, control.ListClientsOptions{KeysetID: "keyset-1"})
	if err != nil || len(listed) != 2 || !reflect.DeepEqual(listed[0].KeysetIDs, []string{"keyset-1"}) || !reflect.DeepEqual(listed[1].KeysetIDs, []string{"keyset-2", "keyset-1"}) {
		t.Fatalf("client grants: %v", err)
	}

	if err := client.DeleteActor(ctx, actor.ID); err != nil {
		t.Fatal(err)
	}

	if err := client.DeleteClient(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestControlFailuresDoNotLeakRetryOrRedirect(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusForbidden)
	client := authenticatedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(int(status.Load()))
		fmt.Fprint(w, `{"error":"CSAKsecret.must-not-leak"}`)
	})
	for _, tc := range []struct {
		status int
		target error
	}{
		{401, control.ErrAuthentication}, {403, control.ErrForbidden}, {404, control.ErrNotFound},
		{409, control.ErrConflict}, {500, control.ErrResponse}, {307, control.ErrResponse},
	} {
		status.Store(int32(tc.status))
		before := calls.Load()
		err := client.DeleteClient(context.Background(), "disposable")
		if !errors.Is(err, tc.target) || strings.Contains(err.Error(), "must-not-leak") {
			t.Fatalf("unsafe or incorrect error: %v", err)
		}

		var httpErr *control.HTTPError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != tc.status || httpErr.Service != "zerokms" {
			t.Fatal("missing HTTP status")
		}

		if calls.Load() != before+1 {
			t.Fatal("write retried or redirected")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := calls.Load()
	if err := client.DeleteClient(ctx, "disposable"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}

	if calls.Load() != before {
		t.Fatal("canceled request reached service")
	}
}

func TestKeysetAndMembershipContracts(t *testing.T) {
	expected := map[string]string{
		"/create-keyset":   `{"name":"tenant","description":"tenant keys","client":{"name":"app","client_type":"device"}}`,
		"/list-keysets":    `{"show_disabled":true}`,
		"/modify-keyset":   `{"keyset_id":"keyset-1","description":""}`,
		"/enable-keyset":   `{"keyset_id":"keyset-1"}`,
		"/disable-keyset":  `{"keyset_id":"keyset-1"}`,
		"/grant-keyset":    `{"keyset_id":"keyset-1","client_id":"client-2"}`,
		"/revoke-keyset":   `{"keyset_id":"keyset-1","client_id":"client-2"}`,
		"/api/memberships": `{"userId":"user-1","role":"member"}`,
	}
	client := authenticatedClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var want, got any
			if err := json.Unmarshal([]byte(expected[r.URL.Path]), &want); err != nil {
				t.Error(err)
			}

			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Error(err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s request differs: %v", r.URL.Path, got)
			}
		}

		switch r.URL.Path {
		case "/create-keyset":
			fmt.Fprint(w, `{"id":"keyset-1","name":"tenant","description":"tenant keys","is_disabled":false,"client":{"id":"client-2","client_key":"encoded-key"}}`)
		case "/list-keysets":
			fmt.Fprint(w, `[{"id":"keyset-1","name":"tenant","description":"tenant keys","is_disabled":true,"is_default":false}]`)
		case "/api/memberships":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, `{"id":"membership-1","sub":"user-1","workspaceId":"ZVATKW3VHMFG27DY"}`)
			} else {
				fmt.Fprint(w, `[{"id":"membership-1","sub":"user-1","workspace_id":"ZVATKW3VHMFG27DY","role":"member"}]`)
			}
		case "/api/memberships/membership-1":
			if r.Method != http.MethodDelete {
				t.Error("membership delete method")
			}

			fmt.Fprint(w, `{}`)
		default:
			if _, ok := expected[r.URL.Path]; !ok {
				t.Errorf("unexpected path %s", r.URL.Path)
			}

			fmt.Fprint(w, `{}`)
		}
	})
	ctx := context.Background()
	created, err := client.CreateKeyset(ctx, control.CreateKeysetOptions{Name: "tenant", Description: "tenant keys", Client: &control.CreateKeysetClientOptions{Name: "app", ClientType: "device"}})
	if err != nil {
		t.Fatal(err)
	}

	if created.ID != "keyset-1" || created.Client == nil || created.Client.ID != "client-2" || created.Client.KeysetID != "keyset-1" {
		t.Fatal("keyset creation metadata lost")
	}

	key, err := created.Client.ExportClientKey()
	if err != nil || string(key) != "encoded-key" {
		t.Fatal("nested creation secret lost")
	}

	clear(key)
	listed, err := client.ListKeysets(ctx, control.ListKeysetsOptions{ShowDisabled: true})
	if err != nil || len(listed) != 1 || !listed[0].IsDisabled || listed[0].IsDefault {
		t.Fatalf("keyset listing: %v", err)
	}

	empty := ""
	for _, call := range []func() error{
		func() error {
			return client.ModifyKeyset(ctx, "keyset-1", control.ModifyKeysetOptions{Description: &empty})
		},
		func() error { return client.EnableKeyset(ctx, "keyset-1") },
		func() error { return client.DisableKeyset(ctx, "keyset-1") },
		func() error { return client.GrantKeyset(ctx, "keyset-1", "client-2") },
		func() error { return client.RevokeKeyset(ctx, "keyset-1", "client-2") },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}

	membership, err := client.CreateMembership(ctx, control.CreateMembershipOptions{UserID: "user-1", Role: "member"})
	if err != nil || membership.ID != "membership-1" || membership.Subject != "user-1" || membership.WorkspaceID != workspace {
		t.Fatalf("created membership: %v", err)
	}

	memberships, err := client.ListMemberships(ctx)
	if err != nil || len(memberships) != 1 || memberships[0].Role != "member" || memberships[0].WorkspaceID != workspace {
		t.Fatalf("listed membership: %v", err)
	}

	if err := client.DeleteMembership(ctx, membership.ID); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidInventoriesAreNotEmptyInventories(t *testing.T) {
	var body atomic.Value
	body.Store("null")
	client := authenticatedClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body.Load().(string))
	})
	ctx := context.Background()
	for _, response := range []string{"null", "{}", "[null]", "[{}]", "["} {
		body.Store(response)
		for _, call := range []func() error{
			func() error { _, err := client.ListKeysets(ctx, control.ListKeysetsOptions{}); return err },
			func() error { _, err := client.ListClients(ctx, control.ListClientsOptions{}); return err },
			func() error { _, err := client.ListAccessKeys(ctx); return err },
			func() error { _, err := client.ListMemberships(ctx); return err },
		} {
			if err := call(); !errors.Is(err, control.ErrResponse) {
				t.Fatalf("invalid inventory %q accepted: %v", response, err)
			}
		}
	}

	for _, response := range []string{`null`, `{}`, `{"items":null}`, `{"items":[{}]}`} {
		body.Store(response)
		if _, err := client.ListActors(ctx, control.ListActorsOptions{}); !errors.Is(err, control.ErrResponse) {
			t.Fatalf("invalid actor inventory accepted: %v", err)
		}
	}

	for _, state := range []string{``, `,"is_disabled":null`} {
		body.Store(`[{"id":"keyset-1","name":"tenant","description":""` + state + `}]`)
		if _, err := client.ListKeysets(ctx, control.ListKeysetsOptions{}); !errors.Is(err, control.ErrResponse) {
			t.Fatalf("missing keyset state accepted: %v", err)
		}
	}

	// Explicit false is valid, and older servers may omit is_default.
	body.Store(`[{"id":"keyset-1","name":"tenant","description":"","is_disabled":false}]`)
	if list, err := client.ListKeysets(ctx, control.ListKeysetsOptions{}); err != nil || len(list) != 1 || list[0].IsDisabled || list[0].IsDefault {
		t.Fatalf("valid keyset defaults rejected: %v", err)
	}

	for _, association := range []string{`null`, `""`, `[null]`, `[""]`, `{}`} {
		body.Store(`[{"id":"client-1","keyset_id":` + association + `}]`)
		if _, err := client.ListClients(ctx, control.ListClientsOptions{}); !errors.Is(err, control.ErrResponse) {
			t.Fatalf("invalid association %s accepted: %v", association, err)
		}
	}

	// A real empty array and a client with no grants remain valid.
	body.Store(`[]`)
	if list, err := client.ListKeysets(ctx, control.ListKeysetsOptions{}); err != nil || len(list) != 0 {
		t.Fatalf("empty inventory: %v", err)
	}

	body.Store(`[{"id":"client-1","keyset_id":[]}]`)
	if list, err := client.ListClients(ctx, control.ListClientsOptions{}); err != nil || len(list) != 1 || len(list[0].KeysetIDs) != 0 {
		t.Fatalf("ungranted client: %v", err)
	}
}

func TestIncompleteCreationResponsesFailWithoutRetry(t *testing.T) {
	var body atomic.Value
	body.Store("{}")
	var calls atomic.Int32
	client := authenticatedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, body.Load().(string))
	})
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		valid    string
		required []string
		call     func() error
	}{
		{"actor", `{"actorId":"actor-1","name":"worker","kind":"app","role":"member","accessKey":"CSAKone.secret"}`,
			[]string{"actorId", "name", "kind", "role", "accessKey"}, func() error {
				out, err := client.CreateActor(ctx, control.CreateActorOptions{Name: "worker", Kind: "app"})
				out.Wipe()

				return err
			}},
		{"client", `{"id":"client-1","name":"app","description":"","dataset_id":"keyset-1","client_key":"encoded-key"}`,
			[]string{"id", "name", "description", "dataset_id", "client_key"}, func() error {
				out, err := client.CreateClient(ctx, control.CreateClientOptions{Name: "app"})
				out.Wipe()

				return err
			}},
		{"keyset", `{"id":"keyset-1","name":"tenant","description":"","is_disabled":false}`,
			[]string{"id", "name", "description", "is_disabled"}, func() error {
				_, err := client.CreateKeyset(ctx, control.CreateKeysetOptions{Name: "tenant"})
				return err
			}},
		{"membership", `{"id":"membership-1","sub":"user-1","workspaceId":"ZVATKW3VHMFG27DY"}`,
			[]string{"id", "sub", "workspaceId"}, func() error {
				_, err := client.CreateMembership(ctx, control.CreateMembershipOptions{UserID: "user-1"})
				return err
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body.Store(tc.valid)
			if err := tc.call(); err != nil {
				t.Fatalf("valid creation rejected: %v", err)
			}

			for _, field := range tc.required {
				for _, missing := range []bool{true, false} {
					var response map[string]any
					if err := json.Unmarshal([]byte(tc.valid), &response); err != nil {
						t.Fatal(err)
					}

					if missing {
						delete(response, field)
					} else {
						response[field] = nil
					}

					encoded, err := json.Marshal(response)
					if err != nil {
						t.Fatal(err)
					}

					body.Store(string(encoded))
					before := calls.Load()
					if err := tc.call(); !errors.Is(err, control.ErrResponse) {
						t.Errorf("incomplete %s (missing=%v) accepted: %v", field, missing, err)
					}

					if calls.Load() != before+1 {
						t.Fatal("creation retried")
					}
				}
			}
		})
	}

	for _, nested := range []string{``, `,"client":null`, `,"client":{}`, `,"client":{"id":"client-1"}`, `,"client":{"client_key":"encoded-key"}`} {
		body.Store(`{"id":"keyset-1","name":"tenant","description":"","is_disabled":false` + nested + `}`)
		before := calls.Load()
		out, err := client.CreateKeyset(ctx, control.CreateKeysetOptions{Name: "tenant", Client: &control.CreateKeysetClientOptions{Name: "app", ClientType: "device"}})
		if out != nil && out.Client != nil {
			out.Client.Wipe()
		}

		if !errors.Is(err, control.ErrResponse) {
			t.Errorf("missing requested client identity or secret accepted: %v", err)
		}

		if calls.Load() != before+1 {
			t.Fatal("keyset creation retried")
		}
	}
}

func TestRefreshedBearerAndEndpointStayPaired(t *testing.T) {
	var endpoints [2]*httptest.Server
	var issued, received [2]atomic.Value
	var requests [2]atomic.Int32
	for i := range endpoints {
		endpoints[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests[i].Add(1)
			received[i].Store(r.Header.Get("Authorization"))
			if r.Method != http.MethodPost || r.URL.Path != "/list-keysets" {
				t.Errorf("unexpected operation: %s %s", r.Method, r.URL.Path)
			}

			fmt.Fprintf(w, `[{"id":"keyset-%d","name":"tenant","description":"","is_disabled":false}]`, i)
		}))
		t.Cleanup(endpoints[i].Close)
	}

	var exchanges atomic.Int32
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/authorise":
			// The first operation refreshes but uses the still-valid old token;
			// the next operation must use the new bearer and endpoint together.
			i := 0
			if exchanges.Add(1) > 1 {
				i = 1
			}

			// Inside the strategy's 90-second refresh window but still valid:
			// exercise real refresh without a sleep or a fake auth strategy.
			expires := time.Now().Add(time.Minute).Unix()
			if i == 1 {
				expires = time.Now().Add(time.Hour).Unix()
			}

			token := serviceJWT(t, issuer.URL, "worker", endpoints[i].URL)
			issued[i].Store("Bearer " + token)
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": token, "expiry": expires})
		default:
			t.Errorf("unexpected auth path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.Close)
	ctx := context.Background()
	store, err := auth.OpenWithoutProfile(ctx, auth.WithRoundTripper(issuer.Client().Transport))
	if errors.Is(err, auth.ErrGuestNotBuilt) {
		t.Skip(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = store.Close() })
	strategy, err := store.AccessKey(ctx, crn, auth.NewAccessKey([]byte("CSAKworker.secret")), auth.WithBaseURL(issuer.URL))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = strategy.Close() })
	client, err := control.NewClient(ctx, crn, control.WithZeroKMSAuth(strategy), control.WithTransport(issuer.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}

	for i := range endpoints {
		keysets, err := client.ListKeysets(ctx, control.ListKeysetsOptions{})
		if err != nil || len(keysets) != 1 || keysets[0].ID != fmt.Sprintf("keyset-%d", i) {
			t.Fatalf("operation %d did not reach its token's endpoint: %v", i, err)
		}

		if received[i].Load() == nil || received[i].Load() != issued[i].Load() {
			t.Fatalf("endpoint %d received the wrong bearer", i)
		}
	}

	if exchanges.Load() != 2 || requests[0].Load() != 1 || requests[1].Load() != 1 {
		t.Fatal("refresh did not move the request to the new endpoint exclusively")
	}
}
