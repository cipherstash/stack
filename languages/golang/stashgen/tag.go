package stashgen

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// The key of the struct tag the generator reads.
const tagKey = "stash"

// tag is one parsed stash tag.
//
//	stash:"-"                                 Omit
//	stash:"context=users"                     Context, on a `_ struct{}` field
//	stash:"context=documents,opaque"          Context and Opaque
//	stash:"email,encrypt_into=TextEq"         Name, VerbEncryptInto, EQLType
//	stash:"notes,encrypt"                     Name, VerbEncrypt
//	stash:"email,encrypt,index=equality;match" Name, VerbEncryptIndex, Indexes
//	stash:"attrs,index=json"                  Name, VerbIndex, Indexes
//	stash:"id,passthrough"                    Name, VerbPassthrough
//	stash:"tenant,context_field"              Name, VerbContextField
//	stash:",passthrough"                      VerbPassthrough with no Name, on an embedded struct
type tag struct {
	Omit    bool
	Context string
	Opaque  bool
	Name    string
	Verb    Verb
	Indexes []Index
	EQLType string
	// Identity is set by a policy only; no tag spells it.
	Identity string
}

// errNoTag reports a field with no stash tag at all.
var errNoTag = errors.New("no stash tag")

// parseTag reads the stash key of a struct tag. It returns errNoTag when the
// key is absent, and a descriptive error when the value does not parse.
func parseTag(structTag string) (tag, error) {
	value, ok := lookupTag(structTag, tagKey)
	if !ok {
		return tag{}, errNoTag
	}
	return parseTagValue(value)
}

// lookupTag reads one key of a struct tag. The generator is a tool, so
// reflect's tag parser is fine here; generated code uses no reflection.
func lookupTag(structTag, key string) (string, bool) {
	return reflect.StructTag(structTag).Lookup(key)
}

func parseTagValue(value string) (tag, error) {
	if value == "-" {
		return tag{Omit: true}, nil
	}
	items, err := splitOutsideParens(value, ',')
	if err != nil {
		return tag{}, err
	}
	if strings.HasPrefix(items[0], "context=") {
		return parseContextTag(items)
	}
	t := tag{Name: items[0]}
	if strings.ContainsAny(t.Name, "=();") {
		return tag{}, fmt.Errorf("tag %q: the first part is the field's name, and %q is not a name", value, t.Name)
	}
	var sawEncrypt, sawPassthrough, sawIndex, sawInto, sawContextField bool
	for _, item := range items[1:] {
		switch {
		case item == "encrypt":
			if sawEncrypt {
				return tag{}, fmt.Errorf("tag %q: encrypt is given twice", value)
			}
			sawEncrypt = true
		case item == "passthrough":
			if sawPassthrough {
				return tag{}, fmt.Errorf("tag %q: passthrough is given twice", value)
			}
			sawPassthrough = true
		case item == "context_field":
			if sawContextField {
				return tag{}, fmt.Errorf("tag %q: context_field is given twice", value)
			}
			sawContextField = true
		case strings.HasPrefix(item, "encrypt_into="):
			if sawInto {
				return tag{}, fmt.Errorf("tag %q: encrypt_into is given twice", value)
			}
			sawInto = true
			t.EQLType = strings.TrimPrefix(item, "encrypt_into=")
			if !isIdent(t.EQLType) {
				return tag{}, fmt.Errorf("tag %q: encrypt_into names an EQL type, and %q is not a type name", value, t.EQLType)
			}
		case strings.HasPrefix(item, "index="):
			if sawIndex {
				return tag{}, fmt.Errorf("tag %q: index is given twice", value)
			}
			sawIndex = true
			t.Indexes, err = parseIndexes(strings.TrimPrefix(item, "index="))
			if err != nil {
				return tag{}, fmt.Errorf("tag %q: %w", value, err)
			}
		case item == "opaque" || strings.HasPrefix(item, "context="):
			return tag{}, fmt.Errorf("tag %q: %s goes on the `_ struct{}` field, as `stash:\"context=...\"`", value, item)
		case item == "":
			return tag{}, fmt.Errorf("tag %q: an empty part", value)
		default:
			return tag{}, fmt.Errorf("tag %q: unknown part %q; the parts are encrypt, encrypt_into=, index=, passthrough, context_field and -", value, item)
		}
	}
	switch {
	case sawContextField && (sawEncrypt || sawInto || sawIndex || sawPassthrough):
		return tag{}, fmt.Errorf("tag %q: a context field is the context of the other fields, stored as it is; it takes no other part", value)
	case sawContextField:
		t.Verb = VerbContextField
		if t.Name == "" {
			return tag{}, fmt.Errorf("tag %q: a context field has a name", value)
		}
		return t, nil
	case sawPassthrough && (sawEncrypt || sawInto):
		return tag{}, fmt.Errorf("tag %q: a field is passthrough or encrypted, not both", value)
	case sawPassthrough && sawIndex:
		return tag{}, fmt.Errorf("tag %q: a passthrough field has no index", value)
	case sawInto && sawEncrypt:
		return tag{}, fmt.Errorf("tag %q: encrypt_into already seals the field; drop encrypt", value)
	case sawInto && sawIndex:
		return tag{}, fmt.Errorf("tag %q: encrypt_into gets its indexes from the EQL type; drop index=", value)
	case sawPassthrough:
		t.Verb = VerbPassthrough
	case sawInto:
		t.Verb = VerbEncryptInto
	case sawEncrypt && sawIndex:
		t.Verb = VerbEncryptIndex
	case sawEncrypt:
		t.Verb = VerbEncrypt
	case sawIndex:
		t.Verb = VerbIndex
	default:
		return tag{}, fmt.Errorf("tag %q: names no verb; add encrypt, encrypt_into=, index= or passthrough", value)
	}
	if t.Name == "" && t.Verb != VerbPassthrough {
		return tag{}, fmt.Errorf("tag %q: a tag with no name goes on an embedded struct, and takes only passthrough", value)
	}
	return t, nil
}

func parseContextTag(items []string) (tag, error) {
	t := tag{Context: strings.TrimPrefix(items[0], "context=")}
	if t.Context == "" {
		return tag{}, fmt.Errorf("tag %q: context= names no context", strings.Join(items, ","))
	}
	for _, item := range items[1:] {
		switch item {
		case "opaque":
			if t.Opaque {
				return tag{}, fmt.Errorf("tag %q: opaque is given twice", strings.Join(items, ","))
			}
			t.Opaque = true
		default:
			return tag{}, fmt.Errorf("tag %q: a context tag takes only opaque, not %q", strings.Join(items, ","), item)
		}
	}
	return t, nil
}

// parseIndexes reads `equality;match(k=3,m=2048)`.
func parseIndexes(list string) ([]Index, error) {
	parts, err := splitOutsideParens(list, ';')
	if err != nil {
		return nil, err
	}
	var indexes []Index
	seen := map[IndexName]bool{}
	for _, part := range parts {
		idx, err := parseIndex(part)
		if err != nil {
			return nil, err
		}
		if seen[idx.Name] {
			return nil, fmt.Errorf("index %s is given twice", idx.Name)
		}
		seen[idx.Name] = true
		indexes = append(indexes, idx)
	}
	return indexes, nil
}

func parseIndex(part string) (Index, error) {
	if part == "" {
		return Index{}, errors.New("index= names no index")
	}
	name, rest := part, ""
	if i := strings.IndexByte(part, '('); i >= 0 {
		if !strings.HasSuffix(part, ")") {
			return Index{}, fmt.Errorf("index %q: options open with ( and do not close", part)
		}
		name, rest = part[:i], part[i+1:len(part)-1]
	}
	idx := Index{Name: IndexName(name)}
	if !knownIndex(idx.Name) {
		return Index{}, fmt.Errorf("unknown index %q; the indexes are equality, match, ore, ope and json", name)
	}
	if rest == "" {
		if strings.HasSuffix(part, "()") {
			return Index{}, fmt.Errorf("index %q: empty options; drop the parentheses", part)
		}
		return idx, nil
	}
	for _, opt := range strings.Split(rest, ",") {
		key, value, _ := strings.Cut(opt, "=")
		if key == "" || !isIdent(key) {
			return Index{}, fmt.Errorf("index %q: option %q is not key or key=value", part, opt)
		}
		idx.Options = append(idx.Options, Option{Key: key, Value: value})
	}
	return idx, nil
}

func knownIndex(name IndexName) bool {
	for _, n := range indexNames {
		if n == name {
			return true
		}
	}
	return false
}

// splitOutsideParens splits s on sep, except inside parentheses.
func splitOutsideParens(s string, sep byte) ([]string, error) {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("tag %q: a ) with no (", s)
			}
		case sep:
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("tag %q: a ( with no )", s)
	}
	return append(parts, s[start:]), nil
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
