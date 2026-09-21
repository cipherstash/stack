package stackencrypt

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The protection is observable from the kernel's side, in
// /proc/self/smaps. The dump exclusion has no limit, so it is asserted on
// every mapping this package reserves; the lock only where the host
// granted it.

// The probe's mapping, on a range committed by Reallocate after the
// mprotect split, not only on what Allocate set up.
func TestGuestMemoryIsLockedAndNotDumpable(t *testing.T) {
	alloc := newMemoryAllocator(bestEffort)
	base, grow, done := probeMemory(t, alloc)
	defer done()
	if _, ok := grow(2); !ok {
		t.Fatal("grow refused")
	}
	assertMappingProtected(t, alloc, base())
}

// The real guest's mapping, once a host-staged buffer has made it grow.
func TestGuestMappingIsLockedAndNotDumpable(t *testing.T) {
	c := rawInstance(t)
	if err := stageLarge(context.Background(), c.inst); err != nil {
		t.Fatal(err)
	}
	assertMappingProtected(t, c.inst.mem, memoryBase(t, c.inst.module.Memory()))
}

// assertMappingProtected checks the smaps entry containing addr: dd
// (MADV_DONTDUMP) whenever there is a reservation at all, and, where the
// lock was granted, lo (mlock) with the whole resident range locked. A
// refused lock skips the second half after the first has run; a failed
// first half fails the test whatever the second does.
func assertMappingProtected(t *testing.T, alloc *memoryAllocator, addr uintptr) {
	t.Helper()
	if alloc.isFallback() {
		t.Skipf("heap fallback in use on this host: %v", alloc.lockError())
	}
	mapping, err := smapsEntry(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !mapping.hasFlag("dd") {
		t.Errorf("VmFlags = %q, want dd (MADV_DONTDUMP)", mapping.vmFlags)
	}
	lockOrSkip(t, alloc)
	if !mapping.hasFlag("lo") {
		t.Errorf("VmFlags = %q, want lo (mlock)", mapping.vmFlags)
	}
	if mapping.lockedKB == 0 || mapping.lockedKB != mapping.rssKB {
		t.Errorf("Locked = %d kB, Rss = %d kB: the committed range is not fully locked", mapping.lockedKB, mapping.rssKB)
	}
}

type smapsMapping struct {
	rssKB, lockedKB uint64
	vmFlags         string
}

func (m smapsMapping) hasFlag(flag string) bool {
	return strings.Contains(" "+m.vmFlags+" ", " "+flag+" ")
}

// smapsEntry finds the /proc/self/smaps mapping containing addr.
func smapsEntry(addr uintptr) (smapsMapping, error) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return smapsMapping{}, err
	}
	defer f.Close()
	var cur smapsMapping
	inside := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if lo, hi, ok := smapsRange(line); ok {
			if inside {
				return cur, nil
			}
			inside = addr >= lo && addr < hi
			cur = smapsMapping{}
			continue
		}
		if !inside {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch key {
		case "Rss":
			cur.rssKB = smapsKB(value)
		case "Locked":
			cur.lockedKB = smapsKB(value)
		case "VmFlags":
			cur.vmFlags = value
		}
	}
	if inside {
		return cur, nil
	}
	return smapsMapping{}, fmt.Errorf("no smaps mapping contains %#x", addr)
}

func smapsRange(line string) (lo, hi uintptr, ok bool) {
	head, _, _ := strings.Cut(line, " ")
	a, b, found := strings.Cut(head, "-")
	if !found {
		return 0, 0, false
	}
	l, err1 := strconv.ParseUint(a, 16, 64)
	h, err2 := strconv.ParseUint(b, 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uintptr(l), uintptr(h), true
}

func smapsKB(value string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSuffix(value, " kB"), 10, 64)
	return n
}
