// Package gensupport holds what only code written by stashgen calls.
//
// A program never imports this package: it calls the functions the generated
// file writes into its own package (users.Encrypt, users.Decrypt,
// users.Fields). The generated file names [GeneratedVersion1], builds a
// [Declaration] from the struct's tags, hands the library its conversions in
// a [Generated] value, and prints through [Redacted] and [RedactedLog]. The
// library lowers the declaration to the data plan the engine reads, sends a
// slice of values as one request, and reports the two notices that the
// generator also prints. No function in this package panics.
package gensupport

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
)

// generatedVersion is the type of the version constants. Only a library
// version that accepts a generated file's layout declares the constant that
// file names, so a file from another version does not compile.
type generatedVersion uint8

// GeneratedVersion1 is the layout of files that stashgen writes today. Every
// generated file holds `const _ = gensupport.GeneratedVersion1`.
const GeneratedVersion1 generatedVersion = 1

// sealed is what a hidden field prints as.
const sealed = "[sealed]"

// Redacted formats a value for String. The shown fields print with their
// values, in name order; the hidden fields print as [sealed]. Generated code
// passes the passthrough fields as shown and the sealed fields as hidden, so
// no plaintext reaches the output.
func Redacted(typeName string, shown map[string]any, hidden ...string) string {
	var b strings.Builder
	b.WriteString(typeName)
	b.WriteByte('{')
	first := true
	for _, name := range sortedKeys(shown) {
		if !first {
			b.WriteString(", ")
		}
		first = false
		fmt.Fprintf(&b, "%s: %v", name, shown[name])
	}
	for _, name := range hidden {
		if !first {
			b.WriteString(", ")
		}
		first = false
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(sealed)
	}
	b.WriteByte('}')
	return b.String()
}

// RedactedLog is [Redacted] for slog: a group with one attribute for each
// shown field, in name order, and the string [sealed] for each hidden field.
func RedactedLog(shown map[string]any, hidden ...string) slog.Value {
	attrs := make([]slog.Attr, 0, len(shown)+len(hidden))
	for _, name := range sortedKeys(shown) {
		attrs = append(attrs, slog.Any(name, shown[name]))
	}
	for _, name := range hidden {
		attrs = append(attrs, slog.String(name, sealed))
	}
	return slog.GroupValue(attrs...)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// notices is where the running program's notices go. Tests replace it.
var (
	noticesMu sync.Mutex
	notices   io.Writer = os.Stderr
	noticed   sync.Map  // notice key -> struct{}
)

// NoticeUntagged prints, once for each type, that the unexported fields are
// neither encrypted nor stored. stashgen printed the same notice when it
// wrote the file, and the file names the fields in a comment. The tag
// `stash:"-"` on each field stops all three.
func NoticeUntagged(typeName string, fields []string) {
	if len(fields) == 0 {
		return
	}
	notice("untagged:"+typeName, fmt.Sprintf(
		"stashgen: %s: not encrypted and not stored: the unexported %s. Tag %s `stash:\"-\"` to confirm that.",
		typeName, fieldList(fields), itOrEach(fields)))
}

// NoticePrintsPlaintext prints, once for each type, that the type prints its
// sealed fields in the clear because it has no String and LogValue methods.
// stashgen printed the same notice when it wrote the file.
func NoticePrintsPlaintext(typeName string) {
	notice("prints:"+typeName, fmt.Sprintf(
		"stashgen: %s prints its sealed fields in the clear: it has no String or LogValue method. Write them, or run stashgen with -redact.",
		typeName))
}

func notice(key, text string) {
	if _, seen := noticed.LoadOrStore(key, struct{}{}); seen {
		return
	}
	noticesMu.Lock()
	defer noticesMu.Unlock()
	fmt.Fprintln(notices, text)
}

func fieldList(fields []string) string {
	quoted := make([]string, len(fields))
	for i, f := range fields {
		quoted[i] = fmt.Sprintf("%q", f)
	}
	if len(quoted) == 1 {
		return "field " + quoted[0]
	}
	return "fields " + strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
}

func itOrEach(fields []string) string {
	if len(fields) == 1 {
		return "it"
	}
	return "each"
}
