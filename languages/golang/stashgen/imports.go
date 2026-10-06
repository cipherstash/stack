package stashgen

import (
	"fmt"
	"sort"
	"strings"
)

// importSet is the imports of the generated file: each path with the name the
// file uses for it.
type importSet struct {
	names map[string]string // path -> name
	paths map[string]string // name -> path
	err   error
}

func newImportSet() *importSet {
	return &importSet{names: map[string]string{}, paths: map[string]string{}}
}

// add records an import and returns the name to use for it. Two packages
// with one name is an error the generator reports before it writes.
func (s *importSet) add(path, name string) string {
	if existing, ok := s.names[path]; ok {
		return existing
	}
	if other, taken := s.paths[name]; taken && other != path {
		if s.err == nil {
			s.err = fmt.Errorf("stashgen: two imports are named %s: %s and %s", name, other, path)
		}
		return name
	}
	s.names[path] = name
	s.paths[name] = path
	return name
}

// block writes the import declaration: the standard library first, then the
// rest, each group sorted by path.
func (s *importSet) block() string {
	var std, rest []string
	for path := range s.names {
		if strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
			rest = append(rest, path)
		} else {
			std = append(std, path)
		}
	}
	sort.Strings(std)
	sort.Strings(rest)
	var b strings.Builder
	b.WriteString("import (\n")
	write := func(path string) {
		name := s.names[path]
		if name != lastElement(path) {
			fmt.Fprintf(&b, "\t%s %q\n", name, path)
		} else {
			fmt.Fprintf(&b, "\t%q\n", path)
		}
	}
	for _, p := range std {
		write(p)
	}
	if len(std) > 0 && len(rest) > 0 {
		b.WriteString("\n")
	}
	for _, p := range rest {
		write(p)
	}
	b.WriteString(")\n")
	return b.String()
}

func lastElement(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}
