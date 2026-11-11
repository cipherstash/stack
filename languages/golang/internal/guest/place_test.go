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

// When an out-slot cannot be written the guest never learns of the buffer,
// so Place must zeroize it in place and clear the pointer slot: the data
// written before the slot failed must not stay in guest memory.
func TestPlaceWipesTheBufferWhenASlotWriteFails(t *testing.T) {
	ctx := context.Background()
	const outOfRange = 1 << 16 // the end of the stub's one page
	for name, slots := range map[string][2]uint32{
		"ptr slot": {outOfRange, 68},
		"len slot": {64, outOfRange},
	} {
		rt := wazero.NewRuntime(ctx)
		m, err := rt.InstantiateWithConfig(ctx, stubGuest(0, nil, withLastError), wazero.NewModuleConfig())
		if err != nil {
			t.Fatal(err)
		}
		if guest.Place(ctx, m, slots[0], slots[1], []byte("secret")) {
			t.Errorf("%s: Place succeeded with an out-of-range slot", name)
		}
		got, _ := m.Memory().Read(allocAt, 6)
		if !bytes.Equal(got, make([]byte, 6)) {
			t.Errorf("%s: buffer left in guest memory: %q", name, got)
		}
		if ptr, _ := m.Memory().ReadUint32Le(64); ptr != 0 {
			t.Errorf("%s: the pointer slot still holds %d", name, ptr)
		}
		_ = rt.Close(ctx)
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
