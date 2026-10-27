package auth

import (
	"encoding/json"
	"fmt"
)

// ServiceToken is a snapshot of a strategy's bearer and decoded metadata.
// Like stack-auth's native client, it does not verify JWT signatures or
// authorize operations. Trust the strategy's CTS configuration and credential
// store. Formatting and JSON serialization do not reveal the bearer.
type ServiceToken struct {
	bearer, workspaceID, workspaceCRN, issuer, zeroKMSURL string
}

// Bearer exposes the bearer credential. The zero value returns "".
// A snapshot does not refresh itself; call [Strategy.ServiceToken] for each operation.
func (t ServiceToken) Bearer() string       { return t.bearer }
func (t ServiceToken) WorkspaceID() string  { return t.workspaceID }
func (t ServiceToken) WorkspaceCRN() string { return t.workspaceCRN }
func (t ServiceToken) Issuer() string       { return t.issuer }
func (t ServiceToken) ZeroKMSURL() string   { return t.zeroKMSURL }

func (ServiceToken) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("ServiceToken(***)")) }
func (ServiceToken) String() string             { return "ServiceToken(***)" }
func (ServiceToken) GoString() string           { return "ServiceToken(***)" }

// This decodes the guest envelope, never a JWT. Metadata is read by the
// existing Rust ServiceToken accessors alongside the bearer it describes.
func decodeServiceToken(data []byte) (ServiceToken, error) {
	var v struct {
		Bearer       string `json:"bearer"`
		WorkspaceID  string `json:"workspace_id"`
		WorkspaceCRN string `json:"workspace_crn"`
		Issuer       string `json:"issuer"`
		ZeroKMSURL   string `json:"zerokms_url"`
	}
	if err := json.Unmarshal(data, &v); err != nil || v.Bearer == "" || v.WorkspaceID == "" || v.WorkspaceCRN == "" || v.Issuer == "" || v.ZeroKMSURL == "" {
		return ServiceToken{}, fmt.Errorf("%w: invalid service token response", ErrInternal)
	}
	return ServiceToken{v.Bearer, v.WorkspaceID, v.WorkspaceCRN, v.Issuer, v.ZeroKMSURL}, nil
}
