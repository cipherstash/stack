package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// StrategyOption configures an auth strategy.
type StrategyOption func(*strategyOptions)

type strategyOptions struct {
	baseURL       string
	cacheCapacity *uint32
}

// WithBaseURL overrides CTS service discovery for one strategy.
func WithBaseURL(url string) StrategyOption {
	return func(o *strategyOptions) { o.baseURL = url }
}

// WithCacheCapacity sets how many distinct IdP JWTs an OIDC strategy keeps
// a CTS token for (1024 unless set). When the cache is full the least
// recently used JWT's token is dropped and that user is exchanged again on
// their next call, so size it to the users one strategy serves within a CTS
// token's lifetime (about 15 minutes); each entry holds that user's JWT and
// CTS token. Zero caches nothing. Only [ProfileStore.OIDC] reads it.
func WithCacheCapacity(n uint32) StrategyOption {
	return func(o *strategyOptions) { o.cacheCapacity = &n }
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
// guest: the source of the bearer token encrypt.NewCredentials takes.
// Close drops its cached credential; closing the parent profile closes all
// its strategies. It is the caller's to close: an encrypt client that
// was given it asks it for tokens but never closes it, so it must stay open
// until the client is closed.
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
		return nil, fmt.Errorf("auth: encode strategy: %w", err)
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
		return nil, ErrConfig
	}
	o := strategyConfig(opts)
	return s.newStrategy(ctx, struct {
		Kind    string `json:"kind"`
		CRN     string `json:"crn"`
		Key     string `json:"access_key"`
		BaseURL string `json:"base_url,omitempty"`
	}{"access_key", crn, key, o.baseURL}, false)
}

// OIDC constructs stack-auth's federation strategy. provider is called on
// every Token call for the IdP JWT of the user that call is for; the
// strategy keeps one CTS token per distinct JWT and mints a new one only
// for a JWT that has no unexpired token. [WithCacheCapacity] sets how many
// JWTs that cache holds.
func (s *ProfileStore) OIDC(ctx context.Context, crn string, provider OIDCProvider, opts ...StrategyOption) (*Strategy, error) {
	if crn == "" || provider == nil {
		return nil, ErrConfig
	}
	o := strategyConfig(opts)
	id := s.root.inst.transport.register(provider)
	config := struct {
		Kind          string  `json:"kind"`
		CRN           string  `json:"crn"`
		Provider      uint32  `json:"provider"`
		BaseURL       string  `json:"base_url,omitempty"`
		CacheCapacity *uint32 `json:"cache_capacity,omitempty"`
	}{"oidc", crn, id, o.baseURL, o.cacheCapacity}
	strategy, err := s.newStrategy(ctx, config, false)
	if err != nil {
		s.root.inst.transport.unregister(id)
		return nil, err
	}
	strategy.providerID = id
	return strategy, nil
}

// DeviceSession uses this workspace store's auth.json. Fresh tokens are read
// without a lock. A refresh takes the same cross-process lock as the Rust
// CLI, then the guest re-reads and saves before the lock is released.
func (s *ProfileStore) DeviceSession(ctx context.Context, opts ...StrategyOption) (*Strategy, error) {
	if s.dir == guestRoot {
		return nil, ErrConfig
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
	crn, crnSet := os.LookupEnv("CS_WORKSPACE_CRN")
	if crnSet {
		_, err := s.callArgs(ctx, func(i *instance) api.Function { return i.authValidateCRN }, guest.BufArg([]byte(crn)))
		if err != nil {
			return nil, err
		}
	}
	if key, keySet := os.LookupEnv("CS_CLIENT_ACCESS_KEY"); keySet {
		if !crnSet {
			return nil, ErrConfig
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
	hasToken, err := workspace.hasToken(ctx)
	if err != nil {
		return nil, err
	}
	if !hasToken {
		return nil, ErrNotAuthenticated
	}
	return workspace.DeviceSession(ctx, opts...)
}

func (s *ProfileStore) hasToken(ctx context.Context) (bool, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.hasToken })
	if err != nil {
		return false, err
	}
	if len(out) != 1 || out[0] > 1 {
		return false, fmt.Errorf("%w: invalid has-token response", ErrInternal)
	}
	return out[0] == 1, nil
}

// Token gets the current CTS bearer credential. Device sessions read a fresh
// token without a file lock; only a refresh call takes the cross-process lock.
func (s *Strategy) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrState
	}
	ctx, status := withAuthHTTPStatus(ctx)
	token, err := s.token(ctx)
	return token, status.wrap(err)
}

// token is Token under the strategy's lock: a read, then a locked refresh
// for a device session that needs one.
func (s *Strategy) token(ctx context.Context) (string, error) {
	call := func(export func(*instance) api.Function) (string, error) {
		out, err := s.store.callArgs(ctx, export, guest.BufArg([]byte(s.handle)))
		if err != nil {
			return "", err
		}
		defer guest.Wipe(out)
		return string(out), nil
	}
	token, err := call(func(i *instance) api.Function { return i.authToken })
	if !s.device || !errors.Is(err, guest.ErrAuthRefreshRequired) {
		return token, err
	}
	path, err := s.store.LockPath(ctx, "auth.json")
	if err != nil {
		return "", err
	}
	err = withRefreshLock(ctx, path, func() error {
		var err error
		token, err = call(func(i *instance) api.Function { return i.authRefresh })
		return err
	})
	return token, err
}

// MemoryLockError is why the memory the strategy lives in is not locked in
// RAM: its ProfileStore's guest, where its token, its access key or refresh
// token, and any client key read through the same store are held. It is
// [ProfileStore.MemoryLockError] of that store, asked now rather than when
// the strategy was made: under best-effort locking the guest can commit
// unlocked memory later, on a growth for a token exchange or a refresh.
// Nil while the memory is locked. It can be asked after Close.
func (s *Strategy) MemoryLockError() error { return s.store.MemoryLockError() }

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
