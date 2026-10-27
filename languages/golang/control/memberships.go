package control

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cipherstash/stack/languages/golang/control/internal/cts"
)

// Membership is a user's role in a workspace, as returned by listing memberships.
type Membership struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Role        string `json:"role"`
	Subject     string `json:"sub"`
}

// CreateMembershipOptions adds a user to the client's workspace.
// Empty Role selects the service default; supported roles are admin, control and member.
type CreateMembershipOptions struct {
	UserID string `json:"userId"`
	Role   string `json:"role,omitempty"`
}

// CreatedMembership contains the creation response. The service does not return
// a role here; use ListMemberships to read the assigned role.
type CreatedMembership struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspaceId"`
	Subject     string `json:"sub"`
}

func (c *Client) CreateMembership(ctx context.Context, opts CreateMembershipOptions) (CreatedMembership, error) {
	input := cts.CreateMembershipRequest{UserId: opts.UserID}
	if opts.Role != "" {
		role := cts.Role(opts.Role)
		input.Role = &role
	}

	var out cts.CreateMembershipResponse
	if err := c.request(ctx, "cts", func(endpoint string) (*http.Request, error) {
		return cts.NewCreateMembershipRequest(endpoint, &cts.CreateMembershipParams{}, input)
	}, &out); err != nil {
		return CreatedMembership{}, err
	}

	if out.Id == "" || out.WorkspaceId == "" || out.Sub == "" {
		return CreatedMembership{}, fmt.Errorf("%w: incomplete create-membership response", ErrResponse)
	}

	return CreatedMembership{ID: out.Id, WorkspaceID: out.WorkspaceId, Subject: out.Sub}, nil
}

func (c *Client) ListMemberships(ctx context.Context) ([]Membership, error) {
	var out cts.ListMembershipsResponse
	if err := c.request(ctx, "cts", func(endpoint string) (*http.Request, error) {
		return cts.NewListMembershipsRequest(endpoint, &cts.ListMembershipsParams{})
	}, &out); err != nil {
		return nil, err
	}

	memberships := make([]Membership, 0, len(out))
	for _, member := range out {
		if member.Id == "" || member.WorkspaceId == "" || member.Sub == "" {
			return nil, fmt.Errorf("%w: missing membership identity", ErrResponse)
		}

		memberships = append(memberships, Membership{ID: member.Id, WorkspaceID: member.WorkspaceId, Subject: member.Sub, Role: member.Role})
	}

	return memberships, nil
}

func (c *Client) DeleteMembership(ctx context.Context, id string) error {
	return c.request(ctx, "cts", func(endpoint string) (*http.Request, error) {
		return cts.NewDeleteMembershipRequest(endpoint, id, &cts.DeleteMembershipParams{})
	}, nil)
}
