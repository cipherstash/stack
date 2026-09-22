package stackauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"github.com/tetratelabs/wazero/api"
)

// Option configures Resolve and Open.
type Option func(*options)

type options struct {
	guest         []byte
	requireLocked bool
}

// WithGuest overrides the embedded wasm module.
func WithGuest(wasm []byte) Option {
	return func(o *options) { o.guest = wasm }
}

// RequireLockedMemory makes Open fail with ErrMemoryLock when the guest's
// memory cannot be locked in RAM or, on Linux, excluded from core dumps,
// instead of continuing with memory that may be swapped or dumped and
// reporting so through [ProfileStore.MemoryLocked]. It holds for the life
// of the store, as stackencrypt's Config.RequireLockedMemory does for a
// client.
func RequireLockedMemory() Option {
	return func(o *options) { o.requireLocked = true }
}

// ProfileStore is a profile directory: the root [Resolve] or [Open] returns,
// or a workspace directory under it from [ProfileStore.WorkspaceStore]. All
// stores from one root share one guest instance over the one mounted
// directory; Close on any of them releases it. It is safe for concurrent
// use; calls are serialised, because a wasm instance is single-threaded.
type ProfileStore struct {
	root *root
	// dir is the store's directory as the guest sees it: guestRoot, or a
	// workspace directory the guest itself named under it.
	dir string
}

// root is the guest instance the stores of one profile share.
type root struct {
	mu      sync.Mutex
	inst    *instance
	hostDir string
	closed  bool
	// released is the runtime's own state, apart from closed: an
	// interrupted call closes the module, and so the stores, while the
	// runtime is still allocated. Close frees it even then.
	released bool
	cleanup  runtime.Cleanup
}

// Resolve opens the profile directory the Rust crate would: CS_CONFIG_PATH
// when set and not blank, else ~/.cipherstash. The directory must exist;
// `stash auth login` creates it.
func Resolve(ctx context.Context, opts ...Option) (*ProfileStore, error) {
	dir := strings.TrimSpace(os.Getenv("CS_CONFIG_PATH"))
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("stackauth: no home directory and CS_CONFIG_PATH is unset: %w", err)
		}
		dir = filepath.Join(home, ".cipherstash")
	}
	return Open(ctx, dir, opts...)
}

// Open instantiates the guest over dir, an existing profile directory,
// mounted as the one directory the guest can see. Nothing is read until a
// method asks; nothing is written unless a method writes.
func Open(ctx context.Context, dir string, opts ...Option) (*ProfileStore, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNoProfile, dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrNoProfile, dir)
	}
	wasm := o.guest
	if wasm == nil {
		if wasm, err = embeddedGuest(); err != nil {
			return nil, err
		}
	}
	inst, err := newInstance(ctx, wasm, dir, guest.PolicyFor(o.requireLocked))
	if err != nil {
		return nil, err
	}
	r := &root{inst: inst, hostDir: dir}
	// The cleanup takes the instance, not the root: a cleanup whose
	// argument reaches its object keeps that object alive forever.
	r.cleanup = runtime.AddCleanup(r, func(inst *instance) { _ = inst.release() }, inst)
	return &ProfileStore{root: r, dir: guestRoot}, nil
}

// Dir is the store's directory on the host: the profile root, or the
// workspace directory under it.
func (s *ProfileStore) Dir() string { return s.hostPath(s.dir) }

// hostPath maps a guest path under the mount to the host path it names.
func (s *ProfileStore) hostPath(guestPath string) string {
	rel := strings.TrimPrefix(guestPath, guestRoot)
	parts := strings.Split(strings.TrimPrefix(rel, "/"), "/")
	return filepath.Join(append([]string{s.root.hostDir}, parts...)...)
}

// MemoryLocked reports whether the guest's memory — where the client key
// and the token pass through — is locked in RAM and, on Linux, excluded
// from core dumps. See stackencrypt's Client.MemoryLocked for what false
// means and what to do about it.
func (s *ProfileStore) MemoryLocked() bool { return s.root.inst.mem.LockError() == nil }

// MemoryLockError is why MemoryLocked is false: an error wrapping
// ErrMemoryLock that names what was refused and the limit that refused it.
// Nil while the memory is locked.
func (s *ProfileStore) MemoryLockError() error {
	if err := s.root.inst.mem.LockError(); err != nil {
		return guest.MemoryLockError(err)
	}
	return nil
}

// String prints the store's directory and memory state. Nothing secret.
func (s *ProfileStore) String() string {
	return fmt.Sprintf("stackauth.ProfileStore{dir: %s, memory: %s}", s.Dir(), s.root.inst.mem)
}

// LogValue implements slog.LogValuer: the directory, and the memory state.
func (s *ProfileStore) LogValue() slog.Value {
	return slog.GroupValue(slog.String("dir", s.Dir()), slog.Any("memory", s.root.inst.mem.LogValue()))
}

// Close releases the guest: its shutdown wipes every buffer it still
// holds, and the runtime close wipes and frees its memory. Idempotent.
// Every store of this profile is closed by it; a call on any of them after
// it fails with ErrState.
func (s *ProfileStore) Close() error {
	r := s.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return nil
	}
	r.released = true
	r.closed = true
	r.cleanup.Stop()
	return r.inst.release()
}

// export selects one of an instance's exports.
type export func(*instance) api.Function

// call runs one export under the profile's lock, closing the profile if
// the guest trapped or an interrupted call took the module down.
func (s *ProfileStore) call(ctx context.Context, fn export, args ...string) ([]byte, error) {
	r := s.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.inst.module.IsClosed() {
		r.closed = true
		return nil, ErrState
	}
	out, err := r.inst.call(ctx, fn(r.inst), append([]string{s.dir}, args...)...)
	switch {
	case r.inst.module.IsClosed():
		r.closed = true
		if err == nil {
			err = ErrState
		}
		err = fmt.Errorf("%w: interrupted call closed the profile", err)
	case errors.Is(err, guest.ErrTrap):
		r.closed = true
		_ = r.inst.module.Close(context.Background())
		err = fmt.Errorf("%w; the profile is closed", err)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CurrentWorkspace is the current workspace id, or ErrNoCurrentWorkspace.
func (s *ProfileStore) CurrentWorkspace(ctx context.Context) (string, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.currentWorkspace })
	return string(out), err
}

// SetCurrentWorkspace makes id the current workspace. The workspace must
// already have profile data on this machine (ErrWorkspaceNotFound
// otherwise): a login creates it, this package never does.
func (s *ProfileStore) SetCurrentWorkspace(ctx context.Context, id string) error {
	_, err := s.call(ctx, func(i *instance) api.Function { return i.setCurrentWorkspace }, id)
	return err
}

// ClearCurrentWorkspace removes the current workspace selection. Nothing
// to remove is not an error.
func (s *ProfileStore) ClearCurrentWorkspace(ctx context.Context) error {
	_, err := s.call(ctx, func(i *instance) api.Function { return i.clearCurrentWorkspace })
	return err
}

// ListWorkspaces is the workspace ids with profile data on disk, sorted.
func (s *ProfileStore) ListWorkspaces(ctx context.Context) ([]string, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.listWorkspaces })
	if err != nil {
		return nil, err
	}
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding the workspace list: %w", ErrInternal, err)
	}
	items, ok := decoded.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: the workspace list is not a list", ErrInternal)
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		id, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%w: a workspace id is not a string", ErrInternal)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// WorkspaceStore is the store scoped to workspace id: the directory
// workspaces/<id> under this store, as the guest names it after validating
// the id (ErrInvalidWorkspaceID otherwise). The directory need not exist
// yet; reads from it report ErrNotFound. It shares this store's guest and
// is closed with it.
func (s *ProfileStore) WorkspaceStore(ctx context.Context, id string) (*ProfileStore, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.workspaceDir }, id)
	if err != nil {
		return nil, err
	}
	return &ProfileStore{root: s.root, dir: string(out)}, nil
}

// CurrentWorkspaceStore is [ProfileStore.WorkspaceStore] for the current
// workspace, or ErrNoCurrentWorkspace.
func (s *ProfileStore) CurrentWorkspaceStore(ctx context.Context) (*ProfileStore, error) {
	id, err := s.CurrentWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	return s.WorkspaceStore(ctx, id)
}

// LockPath is the host path of the lock file the Rust crate takes for
// filename in this store: a sibling `.<filename>.lock`. Nothing is created
// or locked. It is for the host to hold the crate's lock — around a
// refresh, once this package refreshes — since the guest cannot; this
// package never composes a profile path itself.
func (s *ProfileStore) LockPath(ctx context.Context, filename string) (string, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.lockPath }, filename)
	if err != nil {
		return "", err
	}
	return s.hostPath(string(out)), nil
}

// SecretKey reads secretkey.json in this store (a workspace store; the
// root holds none): the ZeroKMS client id and the client key, the latter as
// the opaque [ClientKey] a stackencrypt.Config takes. The transport copy
// of the key is wiped once it is in the ClientKey; the key is then the
// caller's to consume.
func (s *ProfileStore) SecretKey(ctx context.Context) (clientID string, key *ClientKey, err error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.secretKey })
	if err != nil {
		return "", nil, err
	}
	defer guest.Wipe(out)
	fields, err := object(out)
	if err != nil {
		return "", nil, err
	}
	clientID, err = fields.text("client_id")
	if err != nil {
		return "", nil, err
	}
	material, err := fields.text("client_key")
	if err != nil {
		return "", nil, err
	}
	// The one string copy the codec made is the collector's; the bytes the
	// key holds are wiped when it is consumed.
	return clientID, guest.NewClientKey([]byte(material)), nil
}

// DeviceIdentity is the identity the CLI created for this machine, read
// from device.json in this store (the profile root). Read-only: creating
// one is the CLI's.
type DeviceIdentity struct {
	// DeviceInstanceID uniquely identifies this CLI installation.
	DeviceInstanceID string
	// DeviceName is a human-readable name, the hostname by default.
	DeviceName string
}

// DeviceIdentity reads device.json in this store.
func (s *ProfileStore) DeviceIdentity(ctx context.Context) (DeviceIdentity, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.deviceIdentity })
	if err != nil {
		return DeviceIdentity{}, err
	}
	fields, err := object(out)
	if err != nil {
		return DeviceIdentity{}, err
	}
	var d DeviceIdentity
	if d.DeviceInstanceID, err = fields.text("device_instance_id"); err != nil {
		return DeviceIdentity{}, err
	}
	if d.DeviceName, err = fields.text("device_name"); err != nil {
		return DeviceIdentity{}, err
	}
	return d, nil
}

// fields is a decoded codec object.
type fields vcvalue.Object

func object(encoded []byte) (fields, error) {
	decoded, err := vcffi.Unmarshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding the guest's result: %w", ErrInternal, err)
	}
	obj, ok := decoded.(vcvalue.Object)
	if !ok {
		return nil, fmt.Errorf("%w: the guest's result is not an object", ErrInternal)
	}
	return fields(obj), nil
}

func (f fields) get(key string) (any, bool) {
	for _, field := range f {
		if field.Key == key {
			return field.Value, true
		}
	}
	return nil, false
}

// text is a string field that must be present.
func (f fields) text(key string) (string, error) {
	v, ok := f.get(key)
	if !ok {
		return "", fmt.Errorf("%w: the guest's result has no %s", ErrInternal, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s is not a string", ErrInternal, key)
	}
	return s, nil
}

// optionalText is a string field that may be null or absent.
func (f fields) optionalText(key string) (string, error) {
	v, ok := f.get(key)
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s is not a string", ErrInternal, key)
	}
	return s, nil
}

// uint64Field is an unsigned integer field that must be present.
func (f fields) uint64Field(key string) (uint64, error) {
	v, ok := f.get(key)
	if !ok {
		return 0, fmt.Errorf("%w: the guest's result has no %s", ErrInternal, key)
	}
	n, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w: %s is not an integer", ErrInternal, key)
	}
	return n, nil
}
