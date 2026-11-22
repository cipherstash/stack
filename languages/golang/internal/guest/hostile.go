package guest

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/tetratelabs/wazero/api"
)

// The fuzzing seam: what the guest packages' fuzz tests share to call an
// export with pointer/length pairs a correct host would never pass, and to
// check what it answers. Exported because those tests live in the public
// packages, as the testing seam in testing.go is; internal visibility
// keeps it out of any API.
//
// The ABI the guests share (packages/stack-guest-abi, abi.rs) promises:
//
//   - a pair outside linear memory (null with a nonzero length, a range
//     past the end, a range that wraps, a length over isize::MAX) is
//     refused with STATUS_ENCODING, before anything reads it;
//   - a pair inside a buffer the host owns is read as bytes, whatever they
//     hold: the export answers with a defined status or an output, and
//     never traps;
//   - se_dealloc never trusts the host: an unknown pointer is a no-op, a
//     length that does not match is refused, and only an exact match frees.
//
// A pair inside linear memory but outside any buffer the host owns breaks
// the host's side of the contract (an export that wipes its input would
// zero the guest's own memory), so these helpers never build one.

// Param is one parameter of an export: a buffer passed as a (ptr, len)
// pair, or a scalar passed as is.
type Param struct {
	Data   []byte
	Scalar uint64
	IsBuf  bool
}

// Layout names an export's parameters in order: 'p' for a (ptr, len) pair,
// 's' for one scalar.
type Layout string

// pairs is how many (ptr, len) pairs the layout has.
func (l Layout) pairs() int {
	n := 0
	for _, c := range l {
		if c == 'p' {
			n++
		}
	}
	return n
}

// Recorder is fn, recording the parameters of every call as its layout
// names them, read out of guest memory before fn runs. Put it in place of
// an export for one call through the public API, and the recorded
// parameters are what that API sends: a valid call to start from.
type Recorder struct {
	api.Function
	Module api.Module
	Layout Layout
	Got    []Param
}

// Call records the parameters, then calls the export.
func (r *Recorder) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	got := make([]Param, 0, len(r.Layout))
	i := 0
	for _, c := range r.Layout {
		if i >= len(params) {
			break
		}
		if c == 's' {
			got = append(got, Param{Scalar: params[i]})
			i++
			continue
		}
		if i+1 >= len(params) {
			break
		}
		view, _ := r.Module.Memory().Read(uint32(params[i]), uint32(params[i+1])) //nolint:gosec // i32 parameters
		got = append(got, Param{Data: append([]byte(nil), view...), IsBuf: true})
		i += 2
	}
	r.Got = got
	return r.Function.Call(ctx, params...)
}

// PairMode is how FuzzCall builds the fuzzed pair.
type PairMode uint8

const (
	// PairExact passes the fuzzed bytes in a buffer of their own length.
	PairExact PairMode = iota
	// PairInside passes a sub-range of that buffer.
	PairInside
	// PairOutside passes a pair outside linear memory.
	PairOutside
	pairModes
)

// FuzzInput is one fuzzed call: which pair is replaced, how, and with what.
type FuzzInput struct {
	// Slot picks the replaced pair, modulo the layout's pairs.
	Slot uint8
	// Mode picks the PairMode, modulo the modes.
	Mode uint8
	// A and B place the pair: an offset and a length for PairInside, the
	// kind of refusal and its distances for PairOutside.
	A, B uint32
	// Scalar replaces every scalar parameter when ReplaceScalars is set.
	Scalar         uint64
	ReplaceScalars bool
	// Data is the fuzzed buffer.
	Data []byte
}

// ErrBroken marks an answer that breaks the ABI's promises above.
var ErrBroken = errors.New("guest broke its ABI contract")

// FuzzCall calls fn with params, one pair replaced as in names, and checks
// the answer: no trap; ErrEncoding for a pair outside memory; otherwise a
// defined status or an output inside memory. Every buffer it staged, and
// the output, is freed before it returns. onPause, when not nil, is called
// after a STATUS_NEEDS_IO answer so the caller can drop the paused step.
func FuzzCall(ctx context.Context, mem *Allocator, m api.Module, e Exports, fn api.Function, layout Layout, params []Param, in FuzzInput, onPause func()) error {
	if len(params) != len(layout) {
		return fmt.Errorf("%d params for layout %q", len(params), layout)
	}
	mem.Enter()
	defer mem.Exit()
	var staged []Buf
	defer func() {
		for _, b := range staged {
			e.Free(ctx, b)
		}
	}()
	stage := func(data []byte) (Buf, error) {
		b, err := e.AllocWrite(ctx, m, data)
		if err != nil {
			return Buf{}, fmt.Errorf("staging %d bytes: %w", len(data), err)
		}
		staged = append(staged, b)
		return b, nil
	}
	target := -1
	if n := layout.pairs(); n > 0 {
		target = int(in.Slot) % n
	}
	mode := PairMode(in.Mode % uint8(pairModes))
	raw := make([]uint64, 0, 2*len(params))
	pair := 0
	for i, c := range layout {
		if c == 's' {
			v := params[i].Scalar
			if in.ReplaceScalars {
				v = in.Scalar
			}
			raw = append(raw, v)
			continue
		}
		if pair != target {
			b, err := stage(params[i].Data)
			if err != nil {
				return err
			}
			raw = append(raw, uint64(b.Ptr), uint64(b.Len))
			pair++
			continue
		}
		pair++
		var ptr, n uint32
		switch mode {
		case PairOutside:
			ptr, n = OutsidePair(m.Memory().Size(), in.A, in.B)
		default:
			b, err := stage(in.Data)
			if err != nil {
				return err
			}
			ptr, n = b.Ptr, b.Len
			if mode == PairInside {
				ptr, n = InsidePair(b, in.A, in.B)
			}
		}
		raw = append(raw, uint64(ptr), uint64(n))
	}
	res, err := fn.Call(ctx, raw...)
	if err != nil {
		return fmt.Errorf("%w: %s pair %d trapped: %w", ErrBroken, modeName(mode), target, err)
	}
	if len(res) == 0 {
		return fmt.Errorf("%w: no result", ErrBroken)
	}
	ptr, n, status := PackedResult(res[0])
	if mode == PairOutside && target >= 0 {
		if !errors.Is(status, ErrEncoding) {
			return fmt.Errorf("%w: pair %d outside memory answered %v, want %v", ErrBroken, target, status, ErrEncoding)
		}
		return nil
	}
	var unknown unrecognizedStatus
	switch {
	case errors.Is(status, ErrNeedsIO):
		if onPause != nil {
			onPause()
		}
		return nil
	case errors.As(status, &unknown), errors.Is(status, ErrInternal):
		return fmt.Errorf("%w: %s pair %d answered %v", ErrBroken, modeName(mode), target, status)
	case status != nil:
		return nil
	}
	out := Buf{Ptr: ptr, Len: n}
	staged = append(staged, out)
	if _, ok := m.Memory().Read(out.Ptr, out.Len); !ok {
		return fmt.Errorf("%w: output (%#x, %d) is outside memory", ErrBroken, out.Ptr, out.Len)
	}
	return nil
}

func modeName(m PairMode) string {
	switch m {
	case PairExact:
		return "exact"
	case PairInside:
		return "inside"
	default:
		return "outside"
	}
}

// InsidePair is a sub-range of b: an offset of a modulo its length plus
// one, and a length of c modulo what is left plus one.
func InsidePair(b Buf, a, c uint32) (ptr, n uint32) {
	off := upTo(a, b.Len)
	return b.Ptr + off, upTo(c, b.Len-off)
}

// upTo is v reduced to 0..limit.
func upTo(v, limit uint32) uint32 {
	if limit == math.MaxUint32 {
		return v
	}
	return v % (limit + 1)
}

// OutsidePair is a pair no export may read, for a memory of size bytes,
// chosen by a: null with a nonzero length, a range that ends past the
// memory, a range that wraps the 32-bit address space, or a length over
// isize::MAX. A size of zero (wazero's report of a full 4 GiB memory) has
// no end to pass, so only the null and the long pairs are made then.
func OutsidePair(size, a, b uint32) (ptr, n uint32) {
	kind := a % 4
	a /= 4
	if size == 0 && (kind == 1 || kind == 2) {
		kind = 0
	}
	switch kind {
	case 0:
		return 0, b | 1
	case 1:
		// Start up to 64 KiB before the end, and run at least one byte past
		// it.
		back := a % (min(size, 1<<16) + 1)
		start := size - back
		n := uint64(back) + 1 + uint64(b%(1<<20))
		return start, uint32(min(n, math.MaxUint32))
	case 2:
		// Start in the last 4 KiB of the address space, and wrap past it.
		start := uint32(math.MaxUint32) - a%4096
		n := uint64(math.MaxUint32-start) + 2 + uint64(b%4096)
		return start, uint32(min(n, math.MaxUint32))
	default:
		// Longer than isize::MAX on wasm32, from anywhere.
		return 1 + a%max(size, 1), 0x8000_0000 | b
	}
}

// BufferOps is how ExerciseBuffers reads its fuzzed program: three bytes
// per step, an operation and its two arguments.
const BufferOps = 3

// ExerciseBuffers runs a fuzzed sequence of se_alloc and se_dealloc calls
// against a model of the registry, and checks the registry kept every
// promise: no call traps; a small allocation succeeds and overlaps no
// live buffer; one past isize::MAX fails with a null pointer; a free with
// the wrong length, a double free, and a free of a pointer inside or near
// a live buffer leave every live buffer allocated and unwiped. Every
// buffer still live at the end is freed.
func ExerciseBuffers(ctx context.Context, mem *Allocator, m api.Module, e Exports, program []byte) (err error) {
	mem.Enter()
	defer mem.Exit()
	type entry struct {
		b    Buf
		fill byte
	}
	var live, freed []entry
	defer func() {
		for _, l := range live {
			e.Free(ctx, l.b)
		}
	}()
	dealloc := func(ptr, n uint32) error {
		if _, err := e.Dealloc.Call(ctx, uint64(ptr), uint64(n)); err != nil {
			return fmt.Errorf("%w: se_dealloc(%#x, %d) trapped: %w", ErrBroken, ptr, n, err)
		}
		// The registry frees an exact match and nothing else.
		for i, l := range live {
			if l.b.Ptr == ptr && l.b.Len == n {
				freed = append(freed, l)
				live = append(live[:i], live[i+1:]...)
				break
			}
		}
		return nil
	}
	for i := 0; i+BufferOps <= len(program); i += BufferOps {
		op, x, y := program[i], program[i+1], program[i+2]
		switch op % 6 {
		case 0: // allocate 16 to 4111 bytes, and fill them
			n := 16 + (uint32(x)<<8|uint32(y))%4096
			res, err := e.Alloc.Call(ctx, uint64(n))
			if err != nil {
				return fmt.Errorf("%w: se_alloc(%d) trapped: %w", ErrBroken, n, err)
			}
			b := Buf{Ptr: api.DecodeU32(res[0]), Len: n}
			if b.Ptr == 0 {
				return fmt.Errorf("%w: se_alloc(%d) failed", ErrBroken, n)
			}
			for _, l := range live {
				if b.Ptr < l.b.Ptr+l.b.Len && l.b.Ptr < b.Ptr+b.Len {
					return fmt.Errorf("%w: se_alloc(%d) = %#x overlaps live (%#x, %d)", ErrBroken, n, b.Ptr, l.b.Ptr, l.b.Len)
				}
			}
			fill := byte(len(live)%254) + 1
			if !m.Memory().Write(b.Ptr, fillOf(fill, n)) {
				return fmt.Errorf("%w: se_alloc(%d) = %#x is outside memory", ErrBroken, n, b.Ptr)
			}
			live = append(live, entry{b, fill})
		case 1: // free a live buffer
			if len(live) > 0 {
				l := live[int(x)%len(live)]
				if err := dealloc(l.b.Ptr, l.b.Len); err != nil {
					return err
				}
			}
		case 2: // free a live buffer with the wrong length
			if len(live) > 0 {
				l := live[int(x)%len(live)]
				if err := dealloc(l.b.Ptr, l.b.Len+1+uint32(y)); err != nil {
					return err
				}
			}
		case 3: // free a freed buffer again
			if len(freed) > 0 {
				l := freed[int(x)%len(freed)]
				if err := dealloc(l.b.Ptr, l.b.Len); err != nil {
					return err
				}
			}
		case 4: // free a pointer up to 8 bytes either side of a live buffer's start
			if len(live) > 0 {
				l := live[int(x)%len(live)]
				delta := int64(y%16) - 8
				if delta >= 0 {
					delta++
				}
				if err := dealloc(uint32(int64(l.b.Ptr)+delta), l.b.Len); err != nil { //nolint:gosec // a nearby guest address
					return err
				}
			}
		case 5: // allocate past isize::MAX, or free outside memory
			if x%2 == 0 {
				n := uint64(0x8000_0000) | uint64(y)<<23
				res, err := e.Alloc.Call(ctx, n)
				if err != nil {
					return fmt.Errorf("%w: se_alloc(%#x) trapped: %w", ErrBroken, n, err)
				}
				if p := api.DecodeU32(res[0]); p != 0 {
					return fmt.Errorf("%w: se_alloc(%#x) = %#x, want null", ErrBroken, n, p)
				}
			} else {
				size := m.Memory().Size()
				if err := dealloc(size+uint32(y), uint32(x)); err != nil {
					return err
				}
			}
		}
	}
	for _, l := range live {
		view, ok := m.Memory().Read(l.b.Ptr, l.b.Len)
		if !ok {
			return fmt.Errorf("%w: live (%#x, %d) is outside memory", ErrBroken, l.b.Ptr, l.b.Len)
		}
		for j, v := range view {
			if v != l.fill {
				return fmt.Errorf("%w: live (%#x, %d) changed at byte %d: %#x, want %#x", ErrBroken, l.b.Ptr, l.b.Len, j, v, l.fill)
			}
		}
	}
	return nil
}

func fillOf(b byte, n uint32) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
