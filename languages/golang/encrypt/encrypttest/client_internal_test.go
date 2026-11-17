package encrypttest

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The default seed is a promise: values an application's fixtures sealed
// under it in one release open under the next. Comparing two clients cannot
// show it changed, because both read the changed value, so it is pinned here
// by value. Changing it breaks every stored fixture: do not.
func TestTheDefaultSeedNeverChanges(t *testing.T) {
	const pinned = "d691360b35d1606cd9ddb1035e658932575e269dcd8837f745584ed7b90714a8"
	if got := hex.EncodeToString(defaultSeed[:]); got != pinned {
		t.Fatalf("the default seed is %s, and every release has used %s", got, pinned)
	}
}

// A test build missing from the module is named, with the task that builds it.
func TestAMissingTestBuildNamesItsTask(t *testing.T) {
	_, err := readTestBuild("wasm/not_a_build.wasm", "wasm:guest:build:deterministic")
	if err == nil {
		t.Fatal("a missing build was read")
	}
	if !strings.Contains(err.Error(), "mise run wasm:guest:build:deterministic") {
		t.Fatalf("the error does not name the task to run: %v", err)
	}
}
