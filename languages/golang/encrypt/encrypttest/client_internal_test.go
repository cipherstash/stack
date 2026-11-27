package encrypttest

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// closer counts its Close calls.
type closer struct{ closed int }

func (c *closer) Close() error {
	c.closed++
	return nil
}

// narrow gives back what a constructor built when it is the type asked
// for. A constructor's error comes back unchanged. A value of another type
// is an error, and is closed so that it does not leak.
func TestNarrow(t *testing.T) {
	built := &closer{}
	if got, err := narrow[*closer](built, nil); err != nil || got != built {
		t.Fatalf("narrow = %v, %v; want the value built", got, err)
	}
	if built.closed != 0 {
		t.Fatal("narrow closed the value it gave back")
	}

	failed := errors.New("constructor failed")
	if _, err := narrow[*closer](nil, failed); !errors.Is(err, failed) {
		t.Fatalf("%v, want the constructor's error", err)
	}

	wrong := &closer{}
	_, err := narrow[*strings.Builder](wrong, nil)
	if err == nil || !strings.Contains(err.Error(), "*encrypttest.closer, not *strings.Builder") {
		t.Fatalf("%v, want an error naming both types", err)
	}
	if wrong.closed != 1 {
		t.Fatalf("the value of the wrong type was closed %d times, want 1", wrong.closed)
	}
}

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
