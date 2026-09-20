package stackencrypt

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// The reservation is address space, not memory: nothing is charged against
// the overcommit limit until a range is committed.
const reserveFlags = unix.MAP_NORESERVE

// excludeFromDumps marks the whole reservation MADV_DONTDUMP. The flag
// lives on the mapping and survives the mprotect calls that later split it
// into committed and reserved parts, so once is enough; the smaps test
// pins that on a committed range.
func excludeFromDumps(mapping []byte) error {
	if err := unix.Madvise(mapping, unix.MADV_DONTDUMP); err != nil {
		return fmt.Errorf("excluding guest memory from core dumps: %w", err)
	}
	return nil
}
