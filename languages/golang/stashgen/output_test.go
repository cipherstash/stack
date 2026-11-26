package stashgen

import (
	"path/filepath"
	"runtime"
	"testing"
)

// outputPath keeps a path that names its own root, and joins only a path
// relative to the current directory to the package directory (#1901).
func TestOutputPath(t *testing.T) {
	dir := filepath.Join("work", "users")
	cases := []struct {
		name, output, want string
	}{
		{"a file name", "user_stash.go", filepath.Join(dir, "user_stash.go")},
		{"a relative path", filepath.Join("gen", "user_stash.go"), filepath.Join(dir, "gen", "user_stash.go")},
		{"a relative path out of the package", filepath.Join("..", "user_stash.go"), filepath.Join("work", "user_stash.go")},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases,
			struct{ name, output, want string }{"an absolute path", `C:\out\user_stash.go`, `C:\out\user_stash.go`},
			// Rooted, with no drive: the drive of the current directory.
			struct{ name, output, want string }{"a rooted path", `\out\user_stash.go`, `\out\user_stash.go`},
			// A drive, with no root: relative to that drive's current directory.
			struct{ name, output, want string }{"a drive-relative path", `C:out\user_stash.go`, `C:out\user_stash.go`},
			struct{ name, output, want string }{"a UNC path", `\\host\share\user_stash.go`, `\\host\share\user_stash.go`},
		)
	} else {
		cases = append(cases,
			struct{ name, output, want string }{"an absolute path", "/out/user_stash.go", "/out/user_stash.go"},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := outputPath(dir, c.output); got != c.want {
				t.Errorf("outputPath(%q, %q) = %q, want %q", dir, c.output, got, c.want)
			}
		})
	}
}
