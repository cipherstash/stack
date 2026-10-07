package encrypt

import (
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"sync"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// The guest module is a build artefact of the Rust crate in ./guest,
// copied here by `mise run wasm:guest:build`. It is embedded as a
// directory so the package compiles without it; NewClient reports its
// absence.
//
//go:embed wasm
var guestFS embed.FS

const guestPath = "wasm/stack_encrypt_guest.wasm"

// ErrGuestNotBuilt is returned by NewClient when no guest module is
// embedded.
var ErrGuestNotBuilt = errors.New("encrypt: guest module not built — run `mise run wasm:guest:build`")

func embeddedGuest() ([]byte, error) {
	wasm, err := guestFS.ReadFile(guestPath)
	if err != nil {
		return nil, ErrGuestNotBuilt
	}
	return wasm, nil
}

// One shared compilation cache: only the first instantiation of a given
// module in the process compiles it. Every Client still owns its own
// runtime and instance.
var (
	cacheOnce   sync.Once
	sharedCache wazero.CompilationCache
)

func compilationCache() wazero.CompilationCache {
	cacheOnce.Do(func() { sharedCache = wazero.NewCompilationCache() })
	return sharedCache
}

// instance is one instantiated guest with its exports resolved. It is
// the unsynchronised half of a Client; the Client serialises access.
type instance struct {
	runtime wazero.Runtime
	module  api.Module
	// mem supplied the module's linear memory (internal/guest) and reports
	// on it.
	mem *guest.Allocator

	exports                      guest.Exports
	cipherInit, shutdown, keyset api.Function
	term                         api.Function
	encryptRecord, decryptRecord api.Function
	planCheck, targets           api.Function
}

// guestModuleConfig is the module configuration every guest instance runs
// under. wazero's defaults are deterministic by design (see its
// RATIONALE.md): a WASI random_get backed by math/rand with a fixed seed,
// and clocks that start at a fixed epoch and advance 1ms per read. The
// guest's cipher draws ZeroKMS IVs and AEAD nonces through random_get, so
// the default would hand every instance the same nonce sequence; its
// keyset-name cache expires on clock_time_get, so the default would never
// let a name expire on wall time. Each override below is load-bearing and
// pinned by TestGuestModuleConfigHostSources.
func guestModuleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().
		WithName("stack_encrypt_guest").
		// crypto/rand.Reader: the process CSPRNG, safe for concurrent use.
		WithRandSource(rand.Reader).
		WithSysNanotime().
		WithSysWalltime()
}

// newInstance instantiates wasm with the transport as its host module and
// its linear memory from the guest packages' shared allocator. Under the
// strict policy, memory that cannot be locked fails instantiation with
// ErrMemoryLock.
func newInstance(ctx context.Context, wasm []byte, t *transport, policy guest.LockPolicy) (*instance, error) {
	// WithCloseOnContextDone lets a caller's deadline or cancellation
	// interrupt an in-flight guest call — which otherwise holds the Client's
	// lock against every other user. An interrupted call closes the module,
	// so the Client is done afterwards; the alternative is a wedged process.
	config := wazero.NewRuntimeConfig().
		WithCompilationCache(compilationCache()).
		WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, config)
	// The Must* form of this panics on any error, which is the wrong
	// failure mode for a constructor in a library and would strand the
	// runtime it was instantiating into. No error is reachable here today —
	// the host module is fixed and the runtime is new and private, so there
	// is nothing for it to collide with — so this is the total form of a
	// call that does not currently fail, matching the host transport below.
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("encrypt: instantiating WASI: %w", err)
	}
	if err := t.instantiate(ctx, runtime); err != nil {
		_ = runtime.Close(ctx)
		return nil, err
	}
	// The guest's linear memory comes from the guest packages' allocator,
	// not wazero's default slice: reserved once, locked and non-dumpable
	// where the platform allows, wiped on release. See internal/guest.
	mem := guest.NewAllocator(policy)
	// The guest is a reactor (cdylib): no _start. wazero runs _initialize
	// when present, so guest code runs here too, and the memory must stay
	// mapped until it returns, the same as around a call. Today nothing in
	// _initialize re-enters the guest from Go, which is the only path that
	// frees memory under a suspended guest; the bracket makes that a
	// property of this code rather than of what the guest's constructors
	// happen to call. See guest.Allocator.Free.
	mem.Enter()
	module, err := func() (api.Module, error) {
		defer mem.Exit()
		return runtime.InstantiateWithConfig(experimental.WithMemoryAllocator(ctx, mem), wasm, guestModuleConfig())
	}()
	if err != nil {
		_ = runtime.Close(ctx)
		if g := mem.GrowthRefusal(); g.Refused != 0 {
			return nil, fmt.Errorf("%w: %w", guest.MemoryLockError(g.Reason), err)
		}
		return nil, fmt.Errorf("encrypt: instantiating guest: %w", err)
	}
	if policy == guest.Strict {
		if lerr := mem.LockError(); lerr != nil {
			_ = runtime.Close(ctx)
			return nil, guest.MemoryLockError(lerr)
		}
	}
	inst := &instance{runtime: runtime, module: module, mem: mem}
	exports := map[string]*api.Function{
		"se_alloc":          &inst.exports.Alloc,
		"se_dealloc":        &inst.exports.Dealloc,
		"se_cipher_init":    &inst.cipherInit,
		"se_shutdown":       &inst.shutdown,
		"se_keyset":         &inst.keyset,
		"se_term":           &inst.term,
		"se_encrypt_record": &inst.encryptRecord,
		"se_decrypt_record": &inst.decryptRecord,
		"se_plan_check":     &inst.planCheck,
		"se_targets":        &inst.targets,
	}
	for name, slot := range exports {
		if *slot = module.ExportedFunction(name); *slot == nil {
			_ = runtime.Close(ctx)
			return nil, fmt.Errorf("encrypt: guest is missing export %s", name)
		}
	}
	return inst, nil
}

// release runs the guest's shutdown — the client key and every loaded
// index key wiped inside the instance — and closes the runtime, which
// frees the linear memory through the allocator's wipe. It is what Close
// does, and what the cleanup on an unreachable Client does. A module an
// interrupted call or a trap already closed cannot run se_shutdown; the
// runtime close still wipes and frees its memory, so nothing is left
// behind either way.
func (inst *instance) release() error {
	ctx := context.Background()
	if !inst.module.IsClosed() {
		inst.mem.Enter()
		_, _ = inst.shutdown.Call(ctx)
		inst.mem.Exit()
	}
	return inst.runtime.Close(ctx)
}

// The call plumbing — stage each buffer argument through se_alloc, call,
// copy the output out, wipe and free every buffer before returning — is
// internal/guest's, shared with every guest package so the discipline is
// written once. What follows are this package's names for it.

// errGuestTrap marks a guest export that did not return. See guest.ErrTrap.
var errGuestTrap = guest.ErrTrap

func buf(data []byte) guest.Arg { return guest.BufArg(data) }
func scalar(v uint64) guest.Arg { return guest.ScalarArg(v) }

// call stages every buffer argument, calls fn with the arguments in
// order, and copies the output out before every buffer — inputs and output
// — is wiped and freed. The memory stays mapped for the whole call; see
// guest.Call and guest.Allocator.Free.
func (inst *instance) call(ctx context.Context, fn api.Function, args ...guest.Arg) ([]byte, error) {
	return guest.Call(ctx, inst.mem, inst.module, inst.exports, fn, args...)
}

// wipe zeroes a host buffer.
func wipe(b []byte) { guest.Wipe(b) }
