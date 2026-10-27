// Package control administers CipherStash resources across CTS and ZeroKMS.
// Authentication belongs to auth; encryption belongs to encrypt.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// Client administers one workspace. It borrows its strategies and transport;
// callers must keep their credential stores open until all operations finish.
// It has no token cache and does not retry writes whose outcome is unknown.
type Client struct {
	crn     string
	cts     *auth.Strategy
	zerokms *auth.Strategy
	http    http.Client
}

// ClientOption configures a client's service credentials or HTTP transport.
type ClientOption func(*Client)

// WithCTSAuth supplies credentials for actors, access-key metadata and memberships.
func WithCTSAuth(strategy *auth.Strategy) ClientOption {
	return func(c *Client) { c.cts = strategy }
}

// WithZeroKMSAuth supplies credentials for keysets, clients and grants.
func WithZeroKMSAuth(strategy *auth.Strategy) ClientOption {
	return func(c *Client) { c.zerokms = strategy }
}

// WithTransport replaces administrative HTTP transport, not auth's transport.
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) { c.http.Transport = transport }
}

// NewClient authenticates each configured service and checks its workspace.
// At least one service must be configured. Every operation checks a current
// token again: successful construction is not permanent authorization.
func NewClient(ctx context.Context, crn string, opts ...ClientOption) (*Client, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	c := &Client{crn: crn, http: http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	for _, opt := range opts {
		opt(c)
	}

	if crn == "" || (c.cts == nil && c.zerokms == nil) {
		return nil, fmt.Errorf("%w: specify a workspace CRN and at least one service strategy", ErrConfig)
	}

	for _, service := range []string{"cts", "zerokms"} {
		if (service == "cts" && c.cts != nil) || (service == "zerokms" && c.zerokms != nil) {
			if _, _, err := c.authenticate(ctx, service); err != nil {
				return nil, err
			}
		}
	}

	return c, nil
}

func (c *Client) authenticate(ctx context.Context, service string) (auth.ServiceToken, string, error) {
	strategy := c.cts
	if service == "zerokms" {
		strategy = c.zerokms
	}

	if strategy == nil {
		return auth.ServiceToken{}, "", fmt.Errorf("%w: %s authentication is not configured", ErrConfig, service)
	}

	token, err := strategy.ServiceToken(ctx)
	if err != nil {
		return auth.ServiceToken{}, "", fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	if token.WorkspaceCRN() != c.crn || token.WorkspaceID() == "" || token.Bearer() == "" {
		return auth.ServiceToken{}, "", fmt.Errorf("%w: token does not belong to the client's workspace", ErrAuthentication)
	}

	endpoint := token.Issuer()
	if service == "zerokms" {
		endpoint = token.ZeroKMSURL()
	}

	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return auth.ServiceToken{}, "", fmt.Errorf("%w: %s endpoint must be an HTTPS origin", ErrAuthentication, service)
	}

	return token, strings.TrimSuffix(endpoint, "/"), nil
}

const (
	maxResponseBytes = 8 << 20
	requestTimeout   = 30 * time.Second
)

func (c *Client) request(ctx context.Context, service string, build func(string) (*http.Request, error), output any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	token, endpoint, err := c.authenticate(ctx, service)
	if err != nil {
		return err
	}

	// Build against this operation's endpoint, never a shared mutable base URL.
	req, err := build(endpoint)
	if err != nil {
		return fmt.Errorf("%w: cannot construct %s request", ErrConfig, service)
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token.Bearer())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cipherstash-go/control")

	if service == "cts" {
		// Fill generated workspace parameters from the same snapshot as the
		// bearer, including operations whose schema omits the header.
		req.Header.Set("x-cs-workspace-id", token.WorkspaceID())
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return &transportError{cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Error bodies may echo secrets. They never enter errors or logs.
		return &HTTPError{Service: service, StatusCode: resp.StatusCode}
	}

	if output == nil {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	defer clear(data)

	if err != nil {
		return &transportError{cause: err}
	}

	if len(data) > maxResponseBytes {
		return fmt.Errorf("%w: %s response exceeds 8 MiB", ErrResponse, service)
	}

	if err := json.Unmarshal(data, output); err != nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("%w: malformed %s response", ErrResponse, service)
	}

	return nil
}

// Failure categories are independent of the guest's diagnostic protocol.
var (
	ErrConfig         = errors.New("control: invalid configuration")
	ErrAuthentication = errors.New("control: authentication failed")
	ErrForbidden      = errors.New("control: operation forbidden")
	ErrNotFound       = errors.New("control: resource not found")
	ErrConflict       = errors.New("control: resource conflict")
	ErrTransport      = errors.New("control: transport failed")
	ErrResponse       = errors.New("control: invalid service response")
	ErrSecretConsumed = errors.New("control: creation secret already consumed")
)

// HTTPError exposes the service and status without a potentially secret-bearing body.
type HTTPError struct {
	Service    string
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("control: %s returned HTTP %d", e.Service, e.StatusCode)
}

func (e *HTTPError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrAuthentication
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	default:
		return ErrResponse
	}
}

type transportError struct{ cause error }

func (e *transportError) Error() string        { return ErrTransport.Error() }
func (e *transportError) Unwrap() error        { return e.cause }
func (e *transportError) Is(target error) bool { return target == ErrTransport }
