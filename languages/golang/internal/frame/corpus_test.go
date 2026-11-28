package frame

import (
	"errors"
	"io/fs"
	"os"
	"testing"
)

// The corpora that these tests read are files of the repository, outside
// this Go module. A module that a program downloads therefore does not
// include them. In a downloaded module, a missing corpus is not a failure.
// The function readCorpus reports that the corpus is missing. The caller
// then skips its test, or seeds its fuzz target from testdata alone.
//
// A missing corpus fails the test in the repository. A missing corpus also
// fails where STACK_CONFORMANCE_REQUIRED=1 is set.

// repositoryMarker is the repository's .git, a directory in a clone and a
// file in a worktree. A downloaded module has neither.
const repositoryMarker = "../../../../.git"

// readCorpus returns the corpus at path. The second result is false when the
// corpus is missing outside the repository.
func readCorpus(tb testing.TB, path string) ([]byte, bool) {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err == nil {
		return data, true
	}
	if errors.Is(err, fs.ErrNotExist) && !corpusRequired() {
		tb.Logf("%s is not here, as in a downloaded module: not checked", path)
		return nil, false
	}
	tb.Fatal(err)
	return nil, false
}

// corpusRequired reports whether a missing corpus is a failure. A missing
// corpus is a failure in the repository, and where
// STACK_CONFORMANCE_REQUIRED=1 is set.
func corpusRequired() bool {
	if os.Getenv("STACK_CONFORMANCE_REQUIRED") == "1" {
		return true
	}
	_, err := os.Stat(repositoryMarker)
	return err == nil
}

func TestACorpusIsRequiredInTheRepository(t *testing.T) {
	if _, err := os.Stat(repositoryMarker); err != nil {
		t.Skip("not in the repository")
	}
	if !corpusRequired() {
		t.Fatal("a missing corpus would be skipped in the repository")
	}
	for _, path := range []string{valueCorpus, storageCorpus} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}
