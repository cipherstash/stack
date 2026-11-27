package frame

import (
	"errors"
	"io/fs"
	"os"
	"testing"
)

// The corpora these tests read are files of the repository, outside this Go
// module, so the module a program downloads does not carry them. There a
// missing corpus is not a failure: readCorpus reports it, and the caller
// skips a test, or seeds a fuzz target from its testdata alone. In the
// repository, or with STACK_CONFORMANCE_REQUIRED=1, a missing corpus fails.

// repositoryMarker is the repository's .git, a directory in a clone and a
// file in a worktree. A downloaded module has neither.
const repositoryMarker = "../../../../.git"

// readCorpus is the corpus at path, and false when it is missing outside
// the repository.
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

// corpusRequired reports whether a missing corpus fails: in the repository,
// or when STACK_CONFORMANCE_REQUIRED=1 asks for every corpus.
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
