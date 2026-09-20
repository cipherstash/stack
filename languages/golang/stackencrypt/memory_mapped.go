//go:build unix || windows

package stackencrypt

import "unsafe"

// wipeMapped zeroes a committed range before its mapping is released. The
// stores go to memory that a syscall unmaps straight after, which the
// compiler cannot see through, so they are not dead stores it could drop;
// the volatile-store dance a C wipe needs has no Go equivalent and no need
// here. The slice is kept alive past the stores so nothing reorders the
// wipe after the release.
func wipeMapped(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	_ = unsafe.SliceData(b)
}
