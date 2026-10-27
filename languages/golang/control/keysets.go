package control

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cipherstash/stack/languages/golang/control/internal/zerokms"
)

// Keyset describes a ZeroKMS keyset without exposing key material.
type Keyset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsDisabled  bool   `json:"is_disabled"`
	IsDefault   bool   `json:"is_default"`
}

// CreateKeysetClientOptions requests a client alongside a new keyset.
// ClientType must be "device", the service's supported client type.
type CreateKeysetClientOptions struct {
	Name       string `json:"name"`
	ClientType string `json:"client_type"`
}

// CreateKeysetOptions describes a new keyset. A nil Client creates no client.
type CreateKeysetOptions struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Client      *CreateKeysetClientOptions `json:"client,omitempty"`
}

// CreatedKeyset includes an optional client with its once-returned encoded key.
// Extract or wipe that key through Client. Copies share the extraction right.
type CreatedKeyset struct {
	Keyset
	Client *CreatedClient
}

func (c *Client) CreateKeyset(ctx context.Context, opts CreateKeysetOptions) (*CreatedKeyset, error) {
	input := zerokms.CreateKeysetRequest{Name: opts.Name, Description: opts.Description}
	if opts.Client != nil {
		input.Client = &zerokms.CreateClientSpec{Name: opts.Client.Name, ClientType: zerokms.ClientType(opts.Client.ClientType)}
	}

	var out zerokms.CreateKeysetResponse
	if err := c.request(ctx, "zerokms", func(endpoint string) (*http.Request, error) {
		return zerokms.NewCreateKeysetRequest(endpoint, input)
	}, &out); err != nil {
		return nil, err
	}

	if out.Id == "" || out.Name == "" || out.Description == nil || out.IsDisabled == nil {
		return nil, fmt.Errorf("%w: incomplete create-keyset response", ErrResponse)
	}

	if (opts.Client != nil && out.Client == nil) || (out.Client != nil && (out.Client.Id == "" || out.Client.ClientKey == "")) {
		return nil, fmt.Errorf("%w: incomplete created keyset client", ErrResponse)
	}

	created := &CreatedKeyset{Keyset: Keyset{
		ID: out.Id, Name: out.Name, Description: *out.Description,
		IsDisabled: *out.IsDisabled, IsDefault: out.IsDefault != nil && *out.IsDefault,
	}}
	if out.Client != nil {
		// The response contains only the client's ID and key. Its name comes
		// from the request; no description is supplied by this endpoint.
		name := ""
		if opts.Client != nil {
			name = opts.Client.Name
		}

		created.Client = &CreatedClient{
			EncryptionClient: EncryptionClient{ID: out.Client.Id, Name: name, KeysetIDs: []string{out.Id}},
			KeysetID:         out.Id,
			secret:           &creationSecret{bytes: []byte(out.Client.ClientKey)},
		}
	}

	return created, nil
}

type ListKeysetsOptions struct {
	ShowDisabled bool `json:"show_disabled,omitempty"`
}

func (c *Client) ListKeysets(ctx context.Context, opts ListKeysetsOptions) ([]Keyset, error) {
	input := zerokms.ListKeysetRequest{}
	if opts.ShowDisabled {
		input.ShowDisabled = &opts.ShowDisabled
	}

	var out []zerokms.Keyset
	if err := c.request(ctx, "zerokms", func(endpoint string) (*http.Request, error) {
		return zerokms.NewListKeysetsRequest(endpoint, input)
	}, &out); err != nil {
		return nil, err
	}

	keysets := make([]Keyset, 0, len(out))
	for _, keyset := range out {
		if keyset.Id == "" || keyset.Name == "" || keyset.Description == nil || keyset.IsDisabled == nil {
			return nil, fmt.Errorf("%w: incomplete keyset", ErrResponse)
		}

		keysets = append(keysets, Keyset{
			ID: keyset.Id, Name: keyset.Name, Description: *keyset.Description,
			IsDisabled: *keyset.IsDisabled, IsDefault: keyset.IsDefault != nil && *keyset.IsDefault,
		})
	}

	return keysets, nil
}

// ModifyKeysetOptions leaves nil fields unchanged. A non-nil pointer sends
// its value, including an empty string, for the service to validate.
type ModifyKeysetOptions struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// ModifyKeyset changes metadata for the keyset identified by its UUID.
func (c *Client) ModifyKeyset(ctx context.Context, id string, opts ModifyKeysetOptions) error {
	return c.request(ctx, "zerokms", func(endpoint string) (*http.Request, error) {
		return zerokms.NewModifyKeysetRequest(endpoint, zerokms.ModifyKeysetRequest{
			KeysetId: id, Name: opts.Name, Description: opts.Description,
		})
	}, nil)
}

// EnableKeyset enables the keyset identified by its UUID.
func (c *Client) EnableKeyset(ctx context.Context, id string) error {
	return c.request(ctx, "zerokms", func(endpoint string) (*http.Request, error) {
		return zerokms.NewEnableKeysetRequest(endpoint, zerokms.EnableKeysetRequest{KeysetId: id})
	}, nil)
}

// DisableKeyset disables the keyset identified by its UUID; it does not delete it.
func (c *Client) DisableKeyset(ctx context.Context, id string) error {
	return c.request(ctx, "zerokms", func(endpoint string) (*http.Request, error) {
		return zerokms.NewDisableKeysetRequest(endpoint, zerokms.DisableKeysetRequest{KeysetId: id})
	}, nil)
}

// GrantKeyset grants a client access to a keyset. Both IDs are UUID strings.
func (c *Client) GrantKeyset(ctx context.Context, keysetID, clientID string) error {
	return c.request(ctx, "zerokms", func(endpoint string) (*http.Request, error) {
		return zerokms.NewGrantKeysetRequest(endpoint, zerokms.GrantKeysetRequest{KeysetId: keysetID, ClientId: clientID})
	}, nil)
}

// RevokeKeyset revokes a client's access to a keyset. Both IDs are UUID strings.
func (c *Client) RevokeKeyset(ctx context.Context, keysetID, clientID string) error {
	return c.request(ctx, "zerokms", func(endpoint string) (*http.Request, error) {
		return zerokms.NewRevokeKeysetRequest(endpoint, zerokms.RevokeKeysetRequest{KeysetId: keysetID, ClientId: clientID})
	}, nil)
}
