package stackencrypt

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
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
// embedded and none was supplied in Config.Guest.
var ErrGuestNotBuilt = errors.New("stackencrypt: guest module not built — run `mise run wasm:guest:build`")

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

	alloc, dealloc               api.Function
	cipherInit, shutdown, keyset api.Function
	encrypt, encryptElement      api.Function
	decrypt, decryptElement      api.Function
	term                         api.Function
	encryptRecord, decryptRecord api.Function
}

// newInstance instantiates wasm with the transport as its host module.
func newInstance(ctx context.Context, wasm []byte, t *transport) (*instance, error) {
	// WithCloseOnContextDone lets a caller's deadline or cancellation
	// interrupt an in-flight guest call — which otherwise holds the Client's
	// lock against every other user. An interrupted call closes the module,
	// so the Client is done afterwards; the alternative is a wedged process.
	config := wazero.NewRuntimeConfig().
		WithCompilationCache(compilationCache()).
		WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, config)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	if err := t.instantiate(ctx, runtime); err != nil {
		_ = runtime.Close(ctx)
		return nil, err
	}
	// The guest is a reactor (cdylib): no _start. wazero runs _initialize
	// when present.
	module, err := runtime.InstantiateWithConfig(ctx, wasm, wazero.NewModuleConfig().WithName("stack_encrypt_guest"))
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("stackencrypt: instantiating guest: %w", err)
	}
	inst := &instance{runtime: runtime, module: module}
	exports := map[string]*api.Function{
		"se_alloc":           &inst.alloc,
		"se_dealloc":         &inst.dealloc,
		"se_cipher_init":     &inst.cipherInit,
		"se_shutdown":        &inst.shutdown,
		"se_keyset":          &inst.keyset,
		"se_encrypt":         &inst.encrypt,
		"se_encrypt_element": &inst.encryptElement,
		"se_decrypt":         &inst.decrypt,
		"se_decrypt_element": &inst.decryptElement,
		"se_term":            &inst.term,
		"se_encrypt_record":  &inst.encryptRecord,
		"se_decrypt_record":  &inst.decryptRecord,
	}
	for name, slot := range exports {
		if *slot = module.ExportedFunction(name); *slot == nil {
			_ = runtime.Close(ctx)
			return nil, fmt.Errorf("stackencrypt: guest is missing export %s", name)
		}
	}
	return inst, nil
}

func (inst *instance) close(ctx context.Context) error {
	return inst.runtime.Close(ctx)
}

// guestBuf is a host-owned allocation inside guest linear memory.
type guestBuf struct {
	ptr uint32
	len uint32
}

// allocWrite stages data into a fresh guest buffer.
func (inst *instance) allocWrite(ctx context.Context, data []byte) (guestBuf, error) {
	res, err := inst.alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return guestBuf{}, fmt.Errorf("stackencrypt: guest alloc: %w", err)
	}
	buf := guestBuf{ptr: uint32(res[0]), len: uint32(len(data))}
	if buf.ptr == 0 {
		return guestBuf{}, errors.New("stackencrypt: guest allocation failed")
	}
	if len(data) > 0 && !inst.module.Memory().Write(buf.ptr, data) {
		inst.free(ctx, buf)
		return guestBuf{}, errors.New("stackencrypt: guest memory write out of range")
	}
	return buf, nil
}

// free zeroizes and releases a guest buffer (se_dealloc wipes; an unknown
// pointer is a no-op there).
func (inst *instance) free(ctx context.Context, buf guestBuf) {
	if buf.ptr != 0 {
		_, _ = inst.dealloc.Call(ctx, uint64(buf.ptr), uint64(buf.len))
	}
}

// packedResult decodes the guest's packed u64: a non-zero high half is an
// output pointer with the length in the low half; a zero high half carries
// a status code in the low half.
func packedResult(packed uint64) (guestBuf, error) {
	if packed>>32 == 0 {
		return guestBuf{}, statusError(uint32(packed))
	}
	return guestBuf{ptr: uint32(packed >> 32), len: uint32(packed)}, nil
}

// arg is one guest-call argument: a buffer (staged into guest memory and
// passed as a (ptr, len) pair) or a scalar passed as is.
type arg struct {
	data   []byte
	scalar uint64
	isBuf  bool
}

func buf(data []byte) arg { return arg{data: data, isBuf: true} }
func scalar(v uint64) arg { return arg{scalar: v} }

// call stages every buffer argument, calls fn with the arguments in
// order, and copies the output out before every buffer — inputs and output
// — is wiped and freed.
func (inst *instance) call(ctx context.Context, fn api.Function, args ...arg) ([]byte, error) {
	var bufs []guestBuf
	defer func() {
		for _, b := range bufs {
			inst.free(ctx, b)
		}
	}()
	params := make([]uint64, 0, 2*len(args))
	for _, a := range args {
		if !a.isBuf {
			params = append(params, a.scalar)
			continue
		}
		staged, err := inst.allocWrite(ctx, a.data)
		if err != nil {
			return nil, err
		}
		bufs = append(bufs, staged)
		params = append(params, uint64(staged.ptr), uint64(staged.len))
	}
	res, err := fn.Call(ctx, params...)
	if err != nil {
		return nil, fmt.Errorf("stackencrypt: guest call: %w", err)
	}
	out, cerr := packedResult(res[0])
	if cerr != nil {
		return nil, cerr
	}
	bufs = append(bufs, out)
	view, ok := inst.module.Memory().Read(out.ptr, out.len)
	if !ok {
		return nil, errors.New("stackencrypt: guest returned an out-of-range buffer")
	}
	// Copy out before the deferred free wipes the guest-side buffer.
	result := make([]byte, len(view))
	copy(result, view)
	return result, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
