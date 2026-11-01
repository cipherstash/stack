package encrypt_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the real fixture entry points in an isolated tree with their frozen
// inputs but no guest. A missing guest must never make required conformance green.
func TestFixtureConformanceRequiresGuest(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	workdir := filepath.Join(root, "languages", "golang", "encrypt")
	fixtures := filepath.Join("packages", "stack-encrypt", "tests", "fixtures")
	for _, dir := range []string{workdir, filepath.Join(root, fixtures)} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"value_kinds.json", "query_operators.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", fixtures, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, fixtures, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []string{"TestGeneratedCodeOpensTheRustValueKindsFixture", "TestQueryTermsAreTheRustFixtures"}
	for _, required := range []string{"0", "1"} {
		t.Run("required="+required, func(t *testing.T) {
			t.Setenv("STACK_CONFORMANCE_REQUIRED", required)
			cmd := exec.CommandContext(t.Context(), binary, "-test.v", "-test.timeout=30s", "-test.run=^("+strings.Join(tests, "|")+")$")
			cmd.Dir = workdir
			out, err := cmd.CombinedOutput()
			marker := "--- SKIP: "
			if required == "1" {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("required fixtures must fail: %v\n%s", err, out)
				}
				marker = "--- FAIL: "
			} else if err != nil {
				t.Fatalf("optional fixtures must skip: %v\n%s", err, out)
			}
			for _, test := range tests {
				if !strings.Contains(string(out), marker+test) {
					t.Errorf("missing %q result for %s:\n%s", marker, test, out)
				}
			}
			if !strings.Contains(string(out), "deterministic guest not built") {
				t.Errorf("expected missing-guest diagnostic:\n%s", out)
			}
		})
	}
}
