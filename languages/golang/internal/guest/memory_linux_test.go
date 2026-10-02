package guest_test

import (
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/stack/languages/golang/internal/guesttest"
)

// The probe's mapping, on a range committed by Reallocate after the
// mprotect split, not only on what Allocate set up. The real guest's
// mapping is checked the same way where the guest is embedded.
func TestGuestMemoryIsLockedAndNotDumpable(t *testing.T) {
	alloc := guest.NewAllocator(guest.BestEffort)
	base, grow, done := guesttest.ProbeMemory(t, alloc)
	defer done()
	if _, ok := grow(2); !ok {
		t.Fatal("grow refused")
	}
	guesttest.AssertMappingProtected(t, alloc, base())
}
