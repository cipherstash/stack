//go:build unix && !linux

package guest

// Without MAP_NORESERVE the reservation may be charged against a Strict
// overcommit setting on the BSDs; macOS has no such accounting.
const reserveFlags = 0

// excludeFromDumps has no equivalent outside Linux: macOS and the BSDs
// dump every mapping or none. macOS writes no core dumps by default; on a
// host that enables them the operator has chosen to capture memory.
func excludeFromDumps([]byte) error { return nil }
