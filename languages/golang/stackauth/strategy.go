package stackauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// StrategyOption configures an auth strategy.
type StrategyOption func(*strategyOptions)

type strategyOptions struct{ baseURL string }

// WithAuthBaseURL overrides CTS service discovery for one strategy.
func WithAuthBaseURL(url string) StrategyOption {
	return func(o *strategyOptions) { o.baseURL = url }
}

func strategyConfig(opts []StrategyOption) strategyOptions {
	var o strategyOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.baseURL == "" {
		o.baseURL = os.Getenv("CS_CTS_HOST")
	}
	return o
}

// Strategy is a Rust stack-auth strategy retained inside the credential
// guest. Token satisfies stackencrypt.TokenSource. Close drops its cached
// credential; closing the parent profile closes all its strategies.
type Strategy struct {
	store      *ProfileStore
	handle     string
	providerID uint32
	device     bool
	mu         sync.Mutex
	closed     bool
}

func (s *ProfileStore) newStrategy(ctx context.Context, config any, device bool) (*Strategy, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("stackauth: encode strategy: %w", err)
	}
	defer guest.Wipe(data)
	out, err := s.callArgs(ctx, func(i *instance) api.Function { return i.authNew }, guest.BufArg(data))
	if err != nil {
		return nil, err
	}
	if _, err := strconv.ParseUint(string(out), 10, 32); err != nil {
		return nil, fmt.Errorf("%w: invalid auth handle", ErrInternal)
	}
	return &Strategy{store: s, handle: string(out), device: device}, nil
}

// AccessKey constructs stack-auth's access-key strategy for crn. The key
// stays in the guest after construction; it is not sent on each Token call.
func (s *ProfileStore) AccessKey(ctx context.Context, crn, key string, opts ...StrategyOption) (*Strategy, error) {
	if crn == "" || key == "" {
		return nil, ErrAuthConfig
	}
	o := strategyConfig(opts)
	return s.newStrategy(ctx, struct {
		Kind    string `json:"kind"`
		CRN     string `json:"crn"`
		Key     string `json:"access_key"`
		BaseURL string `json:"base_url,omitempty"`
	}{"access_key", crn, key, o.baseURL}, false)
}

// OIDC constructs stack-auth's federation strategy. provider is called for
// a fresh IdP JWT only when the strategy needs to mint a CTS token.
func (s *ProfileStore) OIDC(ctx context.Context, crn string, provider OIDCProvider, opts ...StrategyOption) (*Strategy, error) {
	if crn == "" || provider == nil {
		return nil, ErrAuthConfig
	}
	o := strategyConfig(opts)
	id := s.root.inst.transport.register(provider)
	config := struct {
		Kind     string `json:"kind"`
		CRN      string `json:"crn"`
		Provider uint32 `json:"provider"`
		BaseURL  string `json:"base_url,omitempty"`
	}{"oidc", crn, id, o.baseURL}
	strategy, err := s.newStrategy(ctx, config, false)
	if err != nil {
		s.root.inst.transport.unregister(id)
		return nil, err
	}
	strategy.providerID = id
	return strategy, nil
}

// DeviceSession uses this workspace store's auth.json. Its Token call takes
// the same cross-process lock as the Rust CLI, then the guest re-reads the
// token, exchanges only if necessary, and saves before the lock is released.
func (s *ProfileStore) DeviceSession(ctx context.Context, opts ...StrategyOption) (*Strategy, error) {
	if s.dir == guestRoot {
		return nil, ErrAuthConfig
	}
	o := strategyConfig(opts)
	return s.newStrategy(ctx, struct {
		Kind    string `json:"kind"`
		Dir     string `json:"workspace_dir"`
		BaseURL string `json:"base_url,omitempty"`
	}{"device_session", s.dir, o.baseURL}, true)
}

// Auto follows stack-auth's detection order against the Go host's
// environment: access key first, then the current workspace's device token.
func (s *ProfileStore) Auto(ctx context.Context, opts ...StrategyOption) (*Strategy, error) {
	if key := os.Getenv("CS_CLIENT_ACCESS_KEY"); key != "" {
		crn := os.Getenv("CS_WORKSPACE_CRN")
		if crn == "" {
			return nil, ErrAuthConfig
		}
		return s.AccessKey(ctx, crn, key, opts...)
	}
	workspace, err := s.CurrentWorkspaceStore(ctx)
	if err != nil {
		if errors.Is(err, ErrNoCurrentWorkspace) || errors.Is(err, ErrNoProfile) {
			return nil, ErrNotAuthenticated
		}
		return nil, err
	}
	if _, err := workspace.Token(ctx); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotAuthenticated
		}
		return nil, err
	}
	return workspace.DeviceSession(ctx, opts...)
}

// Token gets the current CTS bearer credential. For a device session the
// host holds the refresh lock over the entire guest call.
func (s *Strategy) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrState
	}
	call := func() (string, error) {
		out, err := s.store.callArgs(ctx, func(i *instance) api.Function { return i.authToken }, guest.BufArg([]byte(s.handle)))
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
	if !s.device {
		return call()
	}
	path, err := s.store.LockPath(ctx, "auth.json")
	if err != nil {
		return "", err
	}
	var token string
	err = withRefreshLock(ctx, path, func() error {
		var err error
		token, err = call()
		return err
	})
	return token, err
}

// Close drops the strategy's cached token and unregisters its provider.
func (s *Strategy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.providerID != 0 {
		s.store.root.inst.transport.unregister(s.providerID)
	}
	_, err := s.store.callArgs(context.Background(), func(i *instance) api.Function { return i.authFree }, guest.BufArg([]byte(s.handle)))
	if errors.Is(err, ErrState) {
		return nil
	}
	return err
}
