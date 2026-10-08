package guest

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/tetratelabs/wazero/api"
)

// The call plumbing every guest package uses to drive an export: stage
// each buffer argument into guest memory through the guest's se_alloc,
// call, copy the output out, and wipe and free every buffer — inputs and
// output — before returning. The memory stays mapped for the whole call
// (see Allocator.Free).

// ErrTrap marks a guest export that did not return: a trap (the guests
// build with panic-as-abort, so an allocation one cannot make or an
// invariant it cannot keep ends in `unreachable`), or a module closed
// under it. The caller closes the instance on it: the guest's state after
// an abort is unknown, and its memory is better wiped than reused.
var ErrTrap = errors.New("cipherstash: guest did not return")

// Buf is a host-owned allocation inside guest linear memory.
type Buf struct {
	Ptr, Len uint32
}

// Arg is one guest-call argument: a buffer (staged into guest memory and
// passed as a (ptr, len) pair) or a scalar passed as is.
type Arg struct {
	data   []byte
	scalar uint64
	isBuf  bool
}

// BufArg is a buffer argument.
func BufArg(data []byte) Arg { return Arg{data: data, isBuf: true} }

// ScalarArg is a scalar argument.
func ScalarArg(v uint64) Arg { return Arg{scalar: v} }

// Exports is the exports every guest package drives, resolved on one module.
type Exports struct {
	Alloc, Dealloc api.Function
	// LastError is se_last_error: the full error behind the last failed
	// export (see Diagnostic). Nil for a guest built before it, which
	// reports the status alone.
	LastError api.Function
}

// AllocWrite stages data into a fresh guest buffer.
func (e Exports) AllocWrite(ctx context.Context, m api.Module, data []byte) (Buf, error) {
	// se_alloc takes an i32: a longer length would reach the guest
	// truncated to its low 32 bits.
	if uint64(len(data)) > math.MaxUint32 {
		return Buf{}, errors.New("cipherstash: buffer exceeds the guest's 4 GiB address space")
	}
	res, err := e.Alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return Buf{}, fmt.Errorf("%w: guest alloc: %w", ErrTrap, err)
	}
	b := Buf{Ptr: api.DecodeU32(res[0]), Len: uint32(len(data))} //nolint:gosec // bounded above
	if b.Ptr == 0 {
		return Buf{}, errors.New("cipherstash: guest allocation failed")
	}
	if len(data) > 0 && !m.Memory().Write(b.Ptr, data) {
		e.Free(ctx, b)
		return Buf{}, errors.New("cipherstash: guest memory write out of range")
	}
	return b, nil
}

// Free zeroizes and releases a guest buffer (se_dealloc wipes; an unknown
// pointer is a no-op there). It runs under a context that cannot be
// cancelled: a caller's deadline expiring after the guest call returned
// must not skip the wipe of the buffers that call staged.
func (e Exports) Free(ctx context.Context, b Buf) {
	if b.Ptr != 0 {
		_, _ = e.Dealloc.Call(context.WithoutCancel(ctx), uint64(b.Ptr), uint64(b.Len))
	}
}

// Call stages every buffer argument, calls fn with the arguments in
// order, and copies the output out before every buffer — inputs and
// output — is wiped and freed. mem is the module's allocator, held
// mapped for the whole call. A failure the guest reports comes back as a
// *Diagnostic wrapping its status's sentinel, or as the sentinel alone
// when the guest gives no detail.
func Call(ctx context.Context, mem *Allocator, m api.Module, e Exports, fn api.Function, args ...Arg) ([]byte, error) {
	mem.Enter()
	defer mem.Exit()
	var bufs []Buf
	defer func() {
		for _, b := range bufs {
			e.Free(ctx, b)
		}
	}()
	params := make([]uint64, 0, 2*len(args))
	for _, a := range args {
		if !a.isBuf {
			params = append(params, a.scalar)
			continue
		}
		staged, err := e.AllocWrite(ctx, m, a.data)
		if err != nil {
			return nil, err
		}
		bufs = append(bufs, staged)
		params = append(params, uint64(staged.Ptr), uint64(staged.Len))
	}
	res, err := fn.Call(ctx, params...)
	if err != nil {
		return nil, fmt.Errorf("%w: guest call: %w", ErrTrap, err)
	}
	ptr, n, err := PackedResult(res[0])
	if err != nil {
		return nil, e.diagnose(ctx, m, err)
	}
	out := Buf{Ptr: ptr, Len: n}
	bufs = append(bufs, out)
	view, ok := m.Memory().Read(out.Ptr, out.Len)
	if !ok {
		return nil, errors.New("cipherstash: guest returned an out-of-range buffer")
	}
	// Copy out before the deferred free wipes the guest-side buffer.
	result := make([]byte, len(view))
	copy(result, view)
	return result, nil
}

// Wipe zeroes a host buffer.
func Wipe(b []byte) {
	clear(b)
}
