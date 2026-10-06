package stashgen

import (
	"strings"
	"unicode"
)

// snakeCase turns a Go name into a column name: ID -> id, CreatedAt ->
// created_at, HTTPServer -> http_server, MedicareNo -> medicare_no. A run of
// capitals is one word until its last letter starts the next word.
func snakeCase(name string) string {
	runes := []rune(name)
	var b strings.Builder
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// lowerFirst lowers a name's first letter: User -> user, ContactRow ->
// contactRow. A leading run of capitals lowers as one: ID -> id, HTTPServer
// -> httpServer.
func lowerFirst(name string) string {
	runes := []rune(name)
	n := 0
	for n < len(runes) && unicode.IsUpper(runes[n]) {
		n++
	}
	if n > 1 && n < len(runes) {
		n--
	}
	for i := 0; i < n; i++ {
		runes[i] = unicode.ToLower(runes[i])
	}
	return string(runes)
}

// wrapComment writes text as a // comment wrapped at width columns.
func wrapComment(text string, width int) string {
	var lines []string
	line := "//"
	for _, word := range strings.Fields(text) {
		if len(line) > 2 && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = "//"
		}
		line += " " + word
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n") + "\n"
}

// goKeywords are the words a local variable cannot be named.
var goKeywords = map[string]bool{
	"break": true, "case": true, "chan": true, "const": true, "continue": true,
	"default": true, "defer": true, "else": true, "fallthrough": true, "for": true,
	"func": true, "go": true, "goto": true, "if": true, "import": true,
	"interface": true, "map": true, "package": true, "range": true, "return": true,
	"select": true, "struct": true, "switch": true, "type": true, "var": true,
}
