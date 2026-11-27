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
// A user needs a tagged version, so the message says that first.
func TestAMissingTestBuildNamesItsTask(t *testing.T) {
	_, err := readTestBuild("wasm/not_a_build.wasm", "wasm:guest:build:deterministic")
	if err == nil {
		t.Fatal("a missing build was read")
	}
	msg := err.Error()
	task := strings.Index(msg, "mise run wasm:guest:build:deterministic")
	if task < 0 {
		t.Fatalf("the error does not name the task to run: %v", err)
	}
	if tagged := strings.Index(msg, "tagged version"); tagged < 0 || tagged > task {
		t.Fatalf("the error does not name a tagged version before the task: %v", err)
	}
	// NewClient refuses an SDK and an encrypttest at different versions, so
	// the advice names both modules.
	for _, module := range []string{
		"github.com/cipherstash/stack/languages/golang and",
		"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest at the same tagged version",
	} {
		if !strings.Contains(msg, module) {
			t.Fatalf("the error does not name %q: %v", module, err)
		}
	}
}
