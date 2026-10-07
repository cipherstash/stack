package encrypt

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// wasiProbe is a hand-assembled module that re-exports the two WASI
// imports the guest's cipher depends on for its security properties, so
// the module configuration can be tested without ZeroKMS and without
// adding a production export to the guest:
//
//	(module
//	  (import "wasi_snapshot_preview1" "random_get"
//	    (func $random_get (param i32 i32) (result i32)))
//	  (import "wasi_snapshot_preview1" "clock_time_get"
//	    (func $clock_time_get (param i32 i64 i32) (result i32)))
//	  (memory (export "memory") 1)
//	  (func (export "random_get") (param i32 i32) (result i32)
//	    local.get 0 local.get 1 call $random_get)
//	  (func (export "clock_time_get") (param i32 i64 i32) (result i32)
//	    local.get 0 local.get 1 local.get 2 call $clock_time_get))
var wasiProbe = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x02, 0x60,
	0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x03, 0x7f, 0x7e, 0x7f, 0x01, 0x7f,
	0x02, 0x4d, 0x02, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65,
	0x74, 0x00, 0x00, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x31, 0x0e, 0x63, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03, 0x03, 0x02, 0x00, 0x01,
	0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x28, 0x03, 0x06, 0x6d, 0x65, 0x6d,
	0x6f, 0x72, 0x79, 0x02, 0x00, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d,
	0x5f, 0x67, 0x65, 0x74, 0x00, 0x02, 0x0e, 0x63, 0x6c, 0x6f, 0x63, 0x6b,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x03, 0x0a,
	0x15, 0x02, 0x08, 0x00, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x0b, 0x0a,
	0x00, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x10, 0x01, 0x0b,
}

// probe instantiates wasiProbe in a fresh runtime under guestModuleConfig,
// exactly as newInstance instantiates the guest.
func probe(t *testing.T, ctx context.Context) (wazero.Runtime, func(n uint32) []byte, func() time.Duration) {
	t.Helper()
	rt := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	mod, err := rt.InstantiateWithConfig(ctx, wasiProbe, guestModuleConfig())
	if err != nil {
		t.Fatalf("instantiating probe: %v", err)
	}
	randomGet := mod.ExportedFunction("random_get")
	clockTimeGet := mod.ExportedFunction("clock_time_get")
	random := func(n uint32) []byte {
		if res, err := randomGet.Call(ctx, 0, uint64(n)); err != nil || res[0] != 0 {
			t.Fatalf("random_get: errno %v err %v", res, err)
		}
		out, ok := mod.Memory().Read(0, n)
		if !ok {
			t.Fatal("reading probe memory")
		}
		return bytes.Clone(out)
	}
	// clock_time_get(id=1 monotonic, precision, out_ptr) writes u64 nanos.
	monotonic := func() time.Duration {
		if res, err := clockTimeGet.Call(ctx, 1, 1, 64); err != nil || res[0] != 0 {
			t.Fatalf("clock_time_get: errno %v err %v", res, err)
		}
		raw, ok := mod.Memory().Read(64, 8)
		if !ok {
			t.Fatal("reading probe memory")
		}
		return time.Duration(binary.LittleEndian.Uint64(raw))
	}
	return rt, random, monotonic
}

// TestGuestModuleConfigHostSources pins that the guest runs on the host's
// CSPRNG and clocks rather than wazero's deterministic defaults. A fixed
// seed would hand every Client the same ZeroKMS IV and AEAD nonce
// sequence; a fake clock would keep the keyset-name cache fresh forever.
func TestGuestModuleConfigHostSources(t *testing.T) {
	ctx := context.Background()
	a, randomA, monotonicA := probe(t, ctx)
	defer a.Close(ctx)
	b, randomB, _ := probe(t, ctx)
	defer b.Close(ctx)

	const n = 32
	first, second := randomA(n), randomB(n)
	if bytes.Equal(first, second) {
		t.Fatalf("two fresh instances drew identical random bytes: %x", first)
	}
	// wazero's default is math/rand seeded with 42; neither instance may
	// start on that stream.
	fake := make([]byte, n)
	if _, err := rand.New(rand.NewSource(42)).Read(fake); err != nil {
		t.Fatal(err)
	}
	for _, got := range [][]byte{first, second} {
		if bytes.Equal(got, fake) {
			t.Fatalf("random_get is wazero's fixed-seed default: %x", got)
		}
	}

	// The fake clock advances 1ms per read regardless of elapsed time, so
	// two reads around a sleep are 1ms apart on it and the whole sleep
	// apart on the host's. The floor is half the sleep, not all of it: on
	// Windows the sleep timer and the monotonic source are different
	// clocks, and a sleep can return a fraction of a millisecond before
	// the monotonic clock says the interval has passed. Half still leaves
	// an order of magnitude between the two answers.
	const sleep = 20 * time.Millisecond
	before := monotonicA()
	time.Sleep(sleep)
	if elapsed := monotonicA() - before; elapsed < sleep/2 {
		t.Fatalf("monotonic clock advanced %v across a %v sleep: not the host clock", elapsed, sleep)
	}
}
