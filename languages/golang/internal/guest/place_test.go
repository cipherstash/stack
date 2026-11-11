package guest_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero"
)

// allocAt is where the stub guest's se_alloc places every buffer.
const allocAt = 4096

// Place stores the buffer in the guest's out-slots and leaves it there for
// the guest to reclaim.
func TestPlaceHandsTheGuestTheBuffer(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer func() { _ = rt.Close(ctx) }()
	m, err := rt.InstantiateWithConfig(ctx, stubGuest(0, nil, withLastError), wazero.NewModuleConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !guest.Place(ctx, m, 64, 68, []byte("secret")) {
		t.Fatal("Place failed on valid slots")
	}
	got, _ := m.Memory().Read(allocAt, 6)
	if string(got) != "secret" {
		t.Fatalf("buffer = %q", got)
	}
	ptr, _ := m.Memory().ReadUint32Le(64)
	n, _ := m.Memory().ReadUint32Le(68)
	if ptr != allocAt || n != 6 {
		t.Fatalf("slots = (%d, %d)", ptr, n)
	}
}

// An out-slot that is out of range is refused before anything is allocated:
// no buffer the guest cannot learn of is left holding the data, and no
// guest memory is spent on it. The stub's se_alloc always returns allocAt,
// so a sentinel there that survives shows the buffer was never allocated or
// written.
func TestPlaceRefusesAnOutOfRangeSlotBeforeAllocating(t *testing.T) {
	ctx := context.Background()
	const outOfRange = 1 << 16 // the end of the stub's one page
	for name, slots := range map[string][2]uint32{
		"ptr slot":      {outOfRange, 68},
		"len slot":      {64, outOfRange},
		"straddle page": {outOfRange - 2, 68},
		"near 4 GiB":    {0xFFFFFFFE, 68},
	} {
		t.Run(name, func(t *testing.T) {
			rt := wazero.NewRuntime(ctx)
			defer func() { _ = rt.Close(ctx) }()
			m, err := rt.InstantiateWithConfig(ctx, stubGuest(0, nil, withLastError), wazero.NewModuleConfig())
			if err != nil {
				t.Fatal(err)
			}
			sentinel := []byte("XXXXXX")
			m.Memory().Write(allocAt, sentinel)
			if guest.Place(ctx, m, slots[0], slots[1], []byte("secret")) {
				t.Fatal("Place succeeded with an out-of-range slot")
			}
			got, _ := m.Memory().Read(allocAt, 6)
			if !bytes.Equal(got, sentinel) {
				t.Fatalf("guest memory at the allocation = %q, want it untouched", got)
			}
			if ptr, _ := m.Memory().ReadUint32Le(64); ptr != 0 {
				t.Fatalf("the pointer slot holds %d", ptr)
			}
		})
	}
}

// An empty value is placed as a zero-length buffer, not refused.
func TestPlaceTakesAnEmptyValue(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer func() { _ = rt.Close(ctx) }()
	m, err := rt.InstantiateWithConfig(ctx, stubGuest(0, nil, withLastError), wazero.NewModuleConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !guest.Place(ctx, m, 64, 68, nil) {
		t.Fatal("Place refused an empty value")
	}
	if n, _ := m.Memory().ReadUint32Le(68); n != 0 {
		t.Fatalf("length slot = %d", n)
	}
}
