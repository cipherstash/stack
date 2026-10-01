package guest

import (
	"math"
	"testing"
)

const wasmPage = 64 * 1024

// The heap fallback keeps the two properties it can: growth wipes the
// slice it abandons, and Free wipes.
func TestHeapMemoryWipesWhatItAbandons(t *testing.T) {
	m := newHeapMemory(wasmPage, 4*wasmPage)
	first, _ := m.commit(wasmPage)
	first[0], first[wasmPage-1] = 0xAA, 0xBB
	second, _ := m.commit(3 * wasmPage)
	if second[0] != 0xAA || second[wasmPage-1] != 0xBB {
		t.Fatal("growth lost the contents")
	}
	if first[0] != 0 || first[wasmPage-1] != 0 {
		t.Fatal("growth left the abandoned slice unwiped")
	}
	if buf, _ := m.commit(5 * wasmPage); buf != nil {
		t.Fatal("grew past max")
	}
	// A size no slice on this host can hold is a refused growth, not a
	// panic. Only a 32-bit host can ask without the request being a real
	// allocation, so that is where it runs (CI's GOARCH=386 pass).
	if uint64(math.MaxInt) < 1<<40 {
		huge := newHeapMemory(0, 1<<40)
		if buf, _ := huge.commit(1 << 40); buf != nil {
			t.Fatal("a growth past the addressable size was granted")
		}
	}
	second[7] = 0xCC
	m.free()
	if second[7] != 0 {
		t.Fatal("free left the slice unwiped")
	}
}
