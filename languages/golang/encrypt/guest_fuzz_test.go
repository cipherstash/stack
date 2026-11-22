package encrypt

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/tetratelabs/wazero/api"
)

// Fuzz tests for the guest's ABI: its exports called with pointer/length
// pairs a correct host never passes, and the buffer registry driven with
// frees a correct host never makes. The rules they hold the guest to are
// internal/guest's (hostile.go). `go test` replays the seeds below and the
// corpus under testdata/fuzz on every run; `mise run go:fuzz` fuzzes.
//
// The guest is the deterministic-kms test build, seeded, so a call that
// gets past its input checks runs the engine to the end with no network.

// fuzzExport is one export of one instance, the layout of its parameters,
// and a valid call to start from.
type fuzzExport struct {
	name   string
	fn     api.Function
	layout guest.Layout
	params []guest.Param
}

// fuzzSeed seeds the deterministic client the fuzz tests run.
var fuzzSeed = [32]byte{7}

// fuzzClient is a seeded client and the exports the fuzz tests call, each
// with the parameters the public API sent it.
type fuzzClient struct {
	c       *Client
	plan    *record.Plan
	exports []fuzzExport
}

// newFuzzClient opens a client and records its exports. The caller closes
// it: a fuzz target keeps one client across its inputs, and replaces it
// when an input breaks it, so its lifetime is the target's, not an
// input's.
func newFuzzClient(tb testing.TB) *fuzzClient {
	tb.Helper()
	ctx := context.Background()
	c, err := NewDeterministicClient(ctx, fuzzSeed)
	if errors.Is(err, ErrDeterministicGuestNotBuilt) {
		tb.Skip(err)
	}
	if err != nil {
		tb.Fatal(err)
	}
	fc := &fuzzClient{c: c, plan: usersPlan()}
	inst := c.inst
	// Each export the public API calls is recorded once, through the API,
	// so a fuzzed call starts from exactly what a correct host sends.
	capture := func(name string, slot *api.Function, layout guest.Layout, call func() error) {
		rec := &guest.Recorder{Function: *slot, Module: inst.module, Layout: layout}
		real := *slot
		*slot = rec
		defer func() { *slot = real }()
		_ = call()
		if len(rec.Got) != len(layout) {
			_ = c.Close()
			tb.Fatalf("%s: recorded %d parameters, want %d", name, len(rec.Got), len(layout))
		}
		fc.exports = append(fc.exports, fuzzExport{name: name, layout: layout, params: rec.Got, fn: real})
	}
	def := c.DefaultKeyset()
	var sealed []record.Sealed
	capture("se_encrypt_record", &inst.encryptRecord, "ppp", func() (err error) {
		sealed, err = def.Seal(ctx, fc.plan, []record.Source{usersRow(34, "alice@example.com")})
		return err
	})
	if len(sealed) != 1 {
		_ = c.Close()
		tb.Fatalf("the seeded client sealed %d rows, want 1", len(sealed))
	}
	capture("se_decrypt_record", &inst.decryptRecord, "ppp", func() error { _, err := def.Open(ctx, fc.plan, sealed); return err })
	capture("se_term", &inst.term, "ppsp", func() error {
		_, err := def.derive(ctx, fc.plan, "email", record.Match, "alice")
		return err
	})
	capture("se_plan_check", &inst.planCheck, "p", func() error { return (&Checker{c: c}).Check(ctx, fc.plan) })
	capture("se_keyset", &inst.keyset, "p", func() error { _, err := c.Keyset(KeysetName("acme")).KeysetID(ctx); return err })
	// Two exports are not recorded. se_cipher_init (which wipes its input
	// in place) runs once, inside NewDeterministicClient, before a
	// recorder can be put in place; its parameter is built here as
	// seededClient builds it, from the same seed, so a valid call
	// re-initialises the same cipher. se_resume (which takes its input as
	// plaintext) runs only after a pause, which this build never makes; it
	// starts from handle 1 and an empty answer. It takes and decodes the
	// answer before it looks at the handle, so the fuzzed pair is read in
	// full, and then answers STATUS_STATE: handle 1 names no paused step.
	seed, err := vcffi.Marshal(fuzzSeed[:])
	if err != nil {
		_ = c.Close()
		tb.Fatal(err)
	}
	fc.exports = append(fc.exports,
		fuzzExport{name: "se_cipher_init", fn: inst.cipherInit, layout: "p", params: []guest.Param{{Data: seed, IsBuf: true}}},
		fuzzExport{name: "se_resume", fn: inst.resume, layout: "sp", params: []guest.Param{{Scalar: 1}, {Data: []byte{}, IsBuf: true}}},
	)
	return fc
}

// keptClient is the client a fuzz target keeps across its inputs: closed
// when the target ends, not when an input does, and replaced when an input
// breaks it.
type keptClient struct{ *fuzzClient }

func keepFuzzClient(f *testing.F) *keptClient {
	k := &keptClient{newFuzzClient(f)}
	f.Cleanup(func() { _ = k.c.Close() })
	return k
}

// replace closes the broken client and opens a new one in its place, so a
// failing input does not fail every input after it.
func (k *keptClient) replace(t *testing.T) {
	t.Helper()
	_ = k.c.Close()
	k.fuzzClient = newFuzzClient(t)
}

// alive is a plan check, which every instance state answers: the guest
// still parses, allocates and answers after the fuzzed call.
func (fc *fuzzClient) alive() error {
	return (&Checker{c: fc.c}).Check(context.Background(), fc.plan)
}

// call makes one fuzzed call on the instance, then checks it is alive.
func (fc *fuzzClient) call(in guest.FuzzInput, which uint8) error {
	ctx := context.Background()
	inst := fc.c.inst
	x := fc.exports[int(which)%len(fc.exports)]
	onPause := func() {
		if step, err := inst.takeIO(ctx); err == nil {
			_, _ = inst.call(ctx, inst.abort, scalar(step.handle))
		}
	}
	if err := guest.FuzzCall(ctx, inst.mem, inst.module, inst.exports, x.fn, x.layout, x.params, in, onPause); err != nil {
		return errors.Join(errors.New(x.name), err)
	}
	if err := fc.alive(); err != nil {
		return errors.Join(errors.New(x.name+": the instance did not survive the call"), err)
	}
	return nil
}

// FuzzGuestExportPairs calls an export with one (ptr, len) pair replaced:
// the fuzzed bytes in a buffer of their own, a sub-range of that buffer,
// or a pair outside linear memory. The exports cover each way the guest
// reads its input: borrowed (se_plan_check, se_keyset, se_decrypt_record),
// borrowed and then wiped in place (se_cipher_init), and taken as
// plaintext and wiped first (se_term, se_encrypt_record, se_resume).
func FuzzGuestExportPairs(f *testing.F) {
	fc := keepFuzzClient(f)
	plan, err := vcffi.Marshal(fc.plan.Wire())
	if err != nil {
		f.Fatal(err)
	}
	for which, x := range fc.exports {
		which := uint8(which) //nolint:gosec // a handful of exports
		// FuzzInput.Slot counts the (ptr, len) pairs, not the parameters,
		// so each pair is seeded with its own recorded bytes.
		var pairs [][]byte
		for _, p := range x.params {
			if p.IsBuf {
				pairs = append(pairs, p.Data)
			}
		}
		for slot, data := range pairs {
			slot := uint8(slot) //nolint:gosec // at most three pairs
			// The recorded parameter itself, a sub-range of it, and each
			// kind of pair outside memory.
			f.Add(which, slot, uint8(guest.PairExact), uint32(0), uint32(0), uint64(0), false, data)
			f.Add(which, slot, uint8(guest.PairInside), uint32(1), uint32(7), uint64(0), false, data)
			for kind := range uint32(4) {
				f.Add(which, slot, uint8(guest.PairOutside), kind, uint32(0xFFFF_FFFF), uint64(0), false, []byte(nil))
			}
		}
		// A plan where another parameter is expected, and a scalar no
		// caller sends (a term kind, a resume handle).
		f.Add(which, uint8(0), uint8(guest.PairExact), uint32(0), uint32(0), uint64(0xFFFF_FFFF), true, plan)
	}
	f.Fuzz(func(t *testing.T, which, slot, mode uint8, a, b uint32, scalar uint64, replace bool, data []byte) {
		in := guest.FuzzInput{Slot: slot, Mode: mode, A: a, B: b, Scalar: scalar, ReplaceScalars: replace, Data: data}
		if err := fc.call(in, which); err != nil {
			fc.replace(t)
			t.Fatal(err)
		}
	})
}

// FuzzGuestBufferRegistry drives se_alloc and se_dealloc with frees a
// correct host never makes: the wrong length, twice, a pointer beside a
// live buffer's start, a pointer outside memory; and allocations too large
// to make. Every live buffer must stay allocated and unchanged.
func FuzzGuestBufferRegistry(f *testing.F) {
	fc := keepFuzzClient(f)
	f.Add([]byte{0, 0, 16, 0, 1, 0, 1, 0, 0, 2, 0, 5, 3, 0, 0, 4, 0, 3})
	f.Add([]byte{0, 15, 255, 0, 0, 0, 1, 1, 0, 3, 0, 0, 0, 0, 0, 4, 1, 0, 4, 1, 15})
	f.Add([]byte{5, 0, 0, 5, 0, 255, 5, 1, 0, 5, 1, 255})
	f.Add([]byte{0, 1, 2, 0, 3, 4, 0, 5, 6, 1, 1, 0, 2, 0, 255, 3, 0, 0, 1, 0, 0, 3, 1, 0})
	f.Fuzz(func(t *testing.T, program []byte) {
		ctx := context.Background()
		inst := fc.c.inst
		if err := guest.ExerciseBuffers(ctx, inst.mem, inst.module, inst.exports, program); err != nil {
			fc.replace(t)
			t.Fatal(err)
		}
		if err := fc.alive(); err != nil {
			fc.replace(t)
			t.Fatalf("the instance did not survive: %v", err)
		}
	})
}
