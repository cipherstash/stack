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

// fuzzExport is one export, the layout of its parameters, and a valid
// call to start from.
type fuzzExport struct {
	name   string
	fn     func(*instance) api.Function
	layout guest.Layout
	params []guest.Param
}

// fuzzClient is a seeded client and the exports the fuzz tests call, each
// with the parameters the public API sent it.
type fuzzClient struct {
	c       *Client
	plan    *record.Plan
	exports []fuzzExport
}

func newFuzzClient(tb testing.TB) *fuzzClient {
	tb.Helper()
	ctx := context.Background()
	c, err := NewDeterministicClient(ctx, [32]byte{7})
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
			tb.Fatalf("%s: recorded %d parameters, want %d", name, len(rec.Got), len(layout))
		}
		fc.exports = append(fc.exports, fuzzExport{name: name, layout: layout, params: rec.Got, fn: exportOf(name)})
	}
	def := c.DefaultKeyset()
	var sealed []record.Sealed
	capture("se_encrypt_record", &inst.encryptRecord, "ppp", func() (err error) {
		sealed, err = def.Seal(ctx, fc.plan, []record.Source{usersRow(34, "alice@example.com")})
		return err
	})
	if len(sealed) != 1 {
		tb.Fatalf("the seeded client sealed %d rows, want 1", len(sealed))
	}
	capture("se_decrypt_record", &inst.decryptRecord, "ppp", func() error { _, err := def.Open(ctx, fc.plan, sealed); return err })
	capture("se_term", &inst.term, "ppsp", func() error {
		_, err := def.derive(ctx, fc.plan, "email", record.Match, "alice")
		return err
	})
	capture("se_plan_check", &inst.planCheck, "p", func() error { return (&Checker{c: c}).Check(ctx, fc.plan) })
	capture("se_keyset", &inst.keyset, "p", func() error { _, err := c.Keyset(KeysetName("acme")).KeysetID(ctx); return err })
	// se_cipher_init (which wipes its input in place) is called once, by
	// NewDeterministicClient, and se_resume (which takes its input as
	// plaintext) only after a pause, which this build never makes: both
	// start from what the client sends them.
	seed, err := vcffi.Marshal(make([]byte, 32))
	if err != nil {
		tb.Fatal(err)
	}
	fc.exports = append(fc.exports,
		fuzzExport{name: "se_cipher_init", fn: exportOf("se_cipher_init"), layout: "p", params: []guest.Param{{Data: seed, IsBuf: true}}},
		fuzzExport{name: "se_resume", fn: exportOf("se_resume"), layout: "sp", params: []guest.Param{{Scalar: 1}, {Data: []byte{}, IsBuf: true}}},
	)
	tb.Cleanup(func() { _ = c.Close() })
	return fc
}

func exportOf(name string) func(*instance) api.Function {
	return func(inst *instance) api.Function {
		switch name {
		case "se_encrypt_record":
			return inst.encryptRecord
		case "se_decrypt_record":
			return inst.decryptRecord
		case "se_term":
			return inst.term
		case "se_plan_check":
			return inst.planCheck
		case "se_keyset":
			return inst.keyset
		case "se_cipher_init":
			return inst.cipherInit
		default:
			return inst.resume
		}
	}
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
	if err := guest.FuzzCall(ctx, inst.mem, inst.module, inst.exports, x.fn(inst), x.layout, x.params, in, onPause); err != nil {
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
	fc := newFuzzClient(f)
	plan, err := vcffi.Marshal(fc.plan.Wire())
	if err != nil {
		f.Fatal(err)
	}
	for which := range uint8(len(fc.exports)) {
		x := fc.exports[which]
		for slot := range uint8(len(x.layout)) {
			// The recorded parameter itself, a sub-range of it, and each
			// kind of pair outside memory.
			var data []byte
			if int(slot) < len(x.params) {
				data = x.params[slot].Data
			}
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
			// A broken instance would fail every input after this one.
			fc = newFuzzClient(t)
			t.Fatal(err)
		}
	})
}

// FuzzGuestBufferRegistry drives se_alloc and se_dealloc with frees a
// correct host never makes: the wrong length, twice, a pointer beside a
// live buffer's start, a pointer outside memory; and allocations too large
// to make. Every live buffer must stay allocated and unchanged.
func FuzzGuestBufferRegistry(f *testing.F) {
	fc := newFuzzClient(f)
	f.Add([]byte{0, 0, 16, 0, 1, 0, 1, 0, 0, 2, 0, 5, 3, 0, 0, 4, 0, 3})
	f.Add([]byte{0, 15, 255, 0, 0, 0, 1, 1, 0, 3, 0, 0, 0, 0, 0, 4, 1, 0, 4, 1, 15})
	f.Add([]byte{5, 0, 0, 5, 0, 255, 5, 1, 0, 5, 1, 255})
	f.Add([]byte{0, 1, 2, 0, 3, 4, 0, 5, 6, 1, 1, 0, 2, 0, 255, 3, 0, 0, 1, 0, 0, 3, 1, 0})
	f.Fuzz(func(t *testing.T, program []byte) {
		ctx := context.Background()
		inst := fc.c.inst
		if err := guest.ExerciseBuffers(ctx, inst.mem, inst.module, inst.exports, program); err != nil {
			fc = newFuzzClient(t)
			t.Fatal(err)
		}
		if err := fc.alive(); err != nil {
			fc = newFuzzClient(t)
			t.Fatalf("the instance did not survive: %v", err)
		}
	})
}
