package stackauth

import (
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"sync"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/experimental/sysfs"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// The guest module is a build artefact of the Rust crate in ./guest,
// copied here by `mise run wasm:auth-guest:build`. It is embedded as a
// directory so the package compiles without it; Open reports its absence.
//
//go:embed wasm
var guestFS embed.FS

const guestPath = "wasm/stack_auth_guest.wasm"

// guestRoot is where the guest sees the profile directory. The one mount
// the guest is given lands here, and every store directory the package
// names is under it. Pinned against the guest's own constant by its tests.
const guestRoot = "/profile"

// ErrGuestNotBuilt is returned by Open when no guest module is embedded and
// none was supplied with [WithGuest].
var ErrGuestNotBuilt = errors.New("stackauth: guest module not built — run `mise run wasm:auth-guest:build`")

func embeddedGuest() ([]byte, error) {
	wasm, err := guestFS.ReadFile(guestPath)
	if err != nil {
		return nil, ErrGuestNotBuilt
	}
	return wasm, nil
}

// One shared compilation cache: only the first instantiation of a given
// module in the process compiles it. Every store still owns its own
// runtime and instance.
var (
	cacheOnce   sync.Once
	sharedCache wazero.CompilationCache
)

func compilationCache() wazero.CompilationCache {
	cacheOnce.Do(func() { sharedCache = wazero.NewCompilationCache() })
	return sharedCache
}

// instance is one instantiated guest over one mounted directory, with its
// exports resolved. It is the unsynchronised half of a store; the root
// serialises access.
type instance struct {
	runtime wazero.Runtime
	module  api.Module
	mem     *guest.Allocator
	exports guest.Exports
	// mount is the one directory the guest sees, confined to itself.
	mount *confinedFS

	shutdown                                                     api.Function
	currentWorkspace, setCurrentWorkspace, clearCurrentWorkspace api.Function
	listWorkspaces, workspaceDir, lockPath                       api.Function
	secretKey, token, deviceIdentity                             api.Function
}

// guestModuleConfig is the module configuration every guest instance runs
// under: the one directory mount, confined to itself (see confinedFS), and
// nothing else that grants a capability. No environment: the guest is told
// its directory, it never looks one up. random_get is wired to crypto/rand
// because wazero's default is a fixed seed: the Rust runtime draws through
// it (its hash maps are seeded from it, for one), and nothing a guest does
// should be predictable across instances. The clocks are the system's for
// the same reason they are in stackencrypt: a deterministic default is the
// wrong default for anything that reads time. Each is pinned by a test.
func guestModuleConfig(mount *confinedFS) wazero.ModuleConfig {
	fsConfig := wazero.NewFSConfig().(sysfs.FSConfig).WithSysFSMount(mount, guestRoot)
	return wazero.NewModuleConfig().
		WithName("stack_auth_guest").
		WithFSConfig(fsConfig).
		WithRandSource(rand.Reader).
		WithSysNanotime().
		WithSysWalltime()
}

// newInstance instantiates wasm with hostDir mounted at guestRoot and its
// linear memory from the guest packages' allocator. Under the strict
// policy, memory that cannot be locked fails instantiation with
// ErrMemoryLock.
func newInstance(ctx context.Context, wasm []byte, hostDir string, policy guest.LockPolicy) (*instance, error) {
	mount, err := newConfinedFS(hostDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNoProfile, hostDir, err)
	}
	config := wazero.NewRuntimeConfig().
		WithCompilationCache(compilationCache()).
		WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, config)
	fail := func(err error) (*instance, error) {
		_ = runtime.Close(ctx)
		_ = mount.Close()
		return nil, err
	}
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		return fail(fmt.Errorf("stackauth: instantiating WASI: %w", err))
	}
	mem := guest.NewAllocator(policy)
	// The guest is a reactor (cdylib): no _start. wazero runs _initialize
	// when present, so guest code runs here too, and the memory must stay
	// mapped until it returns, the same as around a call.
	mem.Enter()
	module, err := func() (api.Module, error) {
		defer mem.Exit()
		return runtime.InstantiateWithConfig(experimental.WithMemoryAllocator(ctx, mem), wasm, guestModuleConfig(mount))
	}()
	if err != nil {
		if g := mem.GrowthRefusal(); g.Refused != 0 {
			return fail(fmt.Errorf("%w: %w", guest.MemoryLockError(g.Reason), err))
		}
		return fail(fmt.Errorf("stackauth: instantiating guest: %w", err))
	}
	if policy == guest.Strict {
		if lerr := mem.LockError(); lerr != nil {
			return fail(guest.MemoryLockError(lerr))
		}
	}
	inst := &instance{runtime: runtime, module: module, mem: mem, mount: mount}
	exports := map[string]*api.Function{
		"se_alloc":                   &inst.exports.Alloc,
		"se_dealloc":                 &inst.exports.Dealloc,
		"sa_shutdown":                &inst.shutdown,
		"sa_current_workspace":       &inst.currentWorkspace,
		"sa_set_current_workspace":   &inst.setCurrentWorkspace,
		"sa_clear_current_workspace": &inst.clearCurrentWorkspace,
		"sa_list_workspaces":         &inst.listWorkspaces,
		"sa_workspace_dir":           &inst.workspaceDir,
		"sa_lock_path":               &inst.lockPath,
		"sa_secret_key":              &inst.secretKey,
		"sa_token":                   &inst.token,
		"sa_device_identity":         &inst.deviceIdentity,
	}
	for name, slot := range exports {
		if *slot = module.ExportedFunction(name); *slot == nil {
			return fail(fmt.Errorf("stackauth: guest is missing export %s", name))
		}
	}
	return inst, nil
}

// release runs the guest's shutdown — every buffer it still holds wiped —
// and closes the runtime, which frees the linear memory through the
// allocator's wipe, then the directory handle the mount holds. A module an
// interrupted call or a trap already closed cannot run sa_shutdown; the
// runtime close still wipes and frees its memory.
func (inst *instance) release() error {
	ctx := context.Background()
	if !inst.module.IsClosed() {
		inst.mem.Enter()
		_, _ = inst.shutdown.Call(ctx)
		inst.mem.Exit()
	}
	err := inst.runtime.Close(ctx)
	if cerr := inst.mount.Close(); err == nil {
		err = cerr
	}
	return err
}

// call drives one export with string arguments, through the shared
// plumbing: staged, called, copied out, wiped.
func (inst *instance) call(ctx context.Context, fn api.Function, args ...string) ([]byte, error) {
	staged := make([]guest.Arg, len(args))
	for i, a := range args {
		staged[i] = guest.BufArg([]byte(a))
	}
	return guest.Call(ctx, inst.mem, inst.module, inst.exports, fn, staged...)
}
