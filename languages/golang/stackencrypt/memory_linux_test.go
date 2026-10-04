package stackencrypt

import (
	"context"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guesttest"
)

// The real guest's mapping, once a host-staged buffer has made it grow:
// excluded from dumps, and locked where the host granted it, as seen from
// /proc/self/smaps. The probe's mapping is checked the same way in
// internal/guest.
func TestGuestMappingIsLockedAndNotDumpable(t *testing.T) {
	c := rawInstance(t)
	if err := stageLarge(context.Background(), c.inst); err != nil {
		t.Fatal(err)
	}
	guesttest.AssertMappingProtected(t, c.inst.mem, guesttest.MemoryBase(t, c.inst.module.Memory()))
}
