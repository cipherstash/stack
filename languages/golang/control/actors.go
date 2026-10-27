package control

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/control/internal/cts"
)

// Actor is a machine identity. Its access-key identifier is a separate value.
type Actor struct {
	ID        string `json:"actorId"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"createdAt"`
}

// CreateActorOptions describes an app or agent and its access-key role.
// Empty Role and nil TokenExpiry select the service defaults.
type CreateActorOptions struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Role        string `json:"role,omitempty"`
	TokenExpiry *int64 `json:"tokenExpiry,omitempty"`
}

// CreatedActor includes the once-returned secret. TakeAccessKey or
// ExportAccessKey consumes it; copies of this result share that ownership.
type CreatedActor struct {
	Actor
	Role   string
	secret *creationSecret
}

// TakeAccessKey transfers the credential directly to an auth strategy's input.
func (a *CreatedActor) TakeAccessKey() (*auth.AccessKey, error) {
	b, err := a.ExportAccessKey()
	if err != nil {
		return nil, err
	}

	return auth.NewAccessKey(b), nil
}

// ExportAccessKey transfers encoded CSAK bytes for persistence. The caller
// owns and must wipe the returned bytes; subsequent extraction fails.
func (a *CreatedActor) ExportAccessKey() ([]byte, error) {
	if a == nil {
		return nil, ErrSecretConsumed
	}

	return a.secret.take()
}

// Wipe discards a creation secret that was not handed off or exported.
func (a *CreatedActor) Wipe() {
	if a != nil {
		a.secret.wipe()
	}
}
func (CreatedActor) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("CreatedActor(***)")) }

func (c *Client) CreateActor(ctx context.Context, opts CreateActorOptions) (*CreatedActor, error) {
	input := cts.CreateActorRequest{Name: opts.Name, Kind: cts.ActorKind(opts.Kind), TokenExpiry: opts.TokenExpiry}
	if opts.Role != "" {
		role := cts.Role(opts.Role)
		input.Role = &role
	}

	var out struct {
		cts.CreateActorResponse
		// Preserve this optional response field, absent from the published schema.
		CreatedAt string `json:"createdAt"`
	}
	if err := c.request(ctx, "cts", func(endpoint string) (*http.Request, error) {
		return cts.NewCreateActorRequest(endpoint, input)
	}, &out); err != nil {
		return nil, err
	}

	if out.ActorId == "" || out.Name == "" || out.Kind == "" || out.Role == "" || out.AccessKey == "" {
		return nil, fmt.Errorf("%w: incomplete create-actor response", ErrResponse)
	}

	return &CreatedActor{
		Actor:  Actor{ID: out.ActorId, Name: out.Name, Kind: string(out.Kind), CreatedAt: out.CreatedAt},
		Role:   string(out.Role),
		secret: &creationSecret{bytes: []byte(out.AccessKey)},
	}, nil
}

type ListActorsOptions struct {
	Limit  int
	Cursor string
}

// ActorPage is one page, not an automatically accumulated workspace inventory.
type ActorPage struct {
	Items      []Actor `json:"items"`
	NextCursor string  `json:"nextCursor"`
}

func (c *Client) ListActors(ctx context.Context, opts ListActorsOptions) (ActorPage, error) {
	params := cts.ListActorsParams{}
	if opts.Limit != 0 {
		params.Limit = &opts.Limit
	}

	if opts.Cursor != "" {
		params.Cursor = &opts.Cursor
	}

	var out cts.ListActorsResponse
	if err := c.request(ctx, "cts", func(endpoint string) (*http.Request, error) {
		return cts.NewListActorsRequest(endpoint, &params)
	}, &out); err != nil {
		return ActorPage{}, err
	}

	if out.Items == nil {
		return ActorPage{}, fmt.Errorf("%w: missing actor list", ErrResponse)
	}

	page := ActorPage{Items: make([]Actor, 0, len(out.Items))}
	if out.NextCursor != nil {
		page.NextCursor = *out.NextCursor
	}

	for _, actor := range out.Items {
		if actor.ActorId == "" || actor.Name == "" {
			return ActorPage{}, fmt.Errorf("%w: missing actor identity", ErrResponse)
		}

		page.Items = append(page.Items, Actor{ID: actor.ActorId, Name: actor.Name, Kind: string(actor.Kind), CreatedAt: actor.CreatedAt})
	}

	return page, nil
}

// DeleteActor deletes the actor and its owned access key.
func (c *Client) DeleteActor(ctx context.Context, id string) error {
	return c.request(ctx, "cts", func(endpoint string) (*http.Request, error) {
		return cts.NewDeleteActorRequest(endpoint, id, &cts.DeleteActorParams{})
	}, nil)
}

// AccessKeyMetadata never contains the access key's secret material.
type AccessKeyMetadata struct {
	ID          string  `json:"keyId"`
	Name        string  `json:"keyName"`
	WorkspaceID string  `json:"workspaceId"`
	Role        string  `json:"role"`
	CreatedAt   string  `json:"createdAt"`
	LastUsedAt  *string `json:"lastUsedAt"`
}

func (c *Client) ListAccessKeys(ctx context.Context) ([]AccessKeyMetadata, error) {
	var out []cts.AccessKey
	if err := c.request(ctx, "cts", func(endpoint string) (*http.Request, error) {
		return cts.NewListAccessKeysRequest(endpoint, &cts.ListAccessKeysParams{})
	}, &out); err != nil {
		return nil, err
	}

	keys := make([]AccessKeyMetadata, 0, len(out))
	for _, key := range out {
		if key.KeyId == "" || key.KeyName == "" {
			return nil, fmt.Errorf("%w: missing access-key identity", ErrResponse)
		}

		keys = append(keys, AccessKeyMetadata{
			ID: key.KeyId, Name: key.KeyName, WorkspaceID: key.WorkspaceId,
			Role: string(key.Role), CreatedAt: key.CreatedAt, LastUsedAt: key.LastUsedAt,
		})
	}

	return keys, nil
}
