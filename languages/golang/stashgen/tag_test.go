package stashgen

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTagEveryFormInTheTable(t *testing.T) {
	cases := []struct {
		in   string
		want tag
	}{
		{`stash:"context=users"`, tag{Context: "users"}},
		{`stash:"email,encrypt_into=TextEq"`, tag{Name: "email", Verb: VerbEncryptInto, EQLType: "TextEq"}},
		{`stash:"notes,encrypt"`, tag{Name: "notes", Verb: VerbEncrypt}},
		{`stash:"email,encrypt,index=equality;match"`, tag{Name: "email", Verb: VerbEncryptIndex,
			Indexes: []Index{{Name: IndexEquality}, {Name: IndexMatch}}}},
		{`stash:"attrs,index=json"`, tag{Name: "attrs", Verb: VerbIndex, Indexes: []Index{{Name: IndexJSON}}}},
		{`stash:"id,passthrough"`, tag{Name: "id", Verb: VerbPassthrough}},
		{`stash:"-"`, tag{Omit: true}},
		{`stash:"context=documents,opaque"`, tag{Context: "documents", Opaque: true}},
		{`stash:",passthrough"`, tag{Verb: VerbPassthrough}},
		// Other libraries' tags around the stash tag do not disturb it.
		{`db:"id" stash:"id,passthrough" gorm:"primaryKey"`, tag{Name: "id", Verb: VerbPassthrough}},
		// The order of the parts after the name does not matter.
		{`stash:"email,index=equality,encrypt"`, tag{Name: "email", Verb: VerbEncryptIndex, Indexes: []Index{{Name: IndexEquality}}}},
		// Options in parentheses, separated by commas inside them.
		{`stash:"email,encrypt,index=equality;match(k=3,m=2048);ore"`, tag{Name: "email", Verb: VerbEncryptIndex,
			Indexes: []Index{{Name: IndexEquality}, {Name: IndexMatch, Options: []Option{{"k", "3"}, {"m", "2048"}}}, {Name: IndexOre}}}},
		{`stash:"attrs,index=json(compat)"`, tag{Name: "attrs", Verb: VerbIndex,
			Indexes: []Index{{Name: IndexJSON, Options: []Option{{Key: "compat"}}}}}},
		{`stash:"body,context=x"`, tag{}}, // error, see below
	}
	for _, c := range cases {
		got, err := parseTag(c.in)
		if c.in == `stash:"body,context=x"` {
			if err == nil {
				t.Errorf("%s: want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if !tagEqual(got, c.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", c.in, got, c.want)
		}
	}
}

func tagEqual(a, b tag) bool {
	if a.Omit != b.Omit || a.Context != b.Context || a.Opaque != b.Opaque || a.Name != b.Name || a.Verb != b.Verb || a.EQLType != b.EQLType {
		return false
	}
	if len(a.Indexes) != len(b.Indexes) {
		return false
	}
	for i := range a.Indexes {
		if a.Indexes[i].String() != b.Indexes[i].String() {
			return false
		}
	}
	return true
}

func TestParseTagAbsent(t *testing.T) {
	_, err := parseTag(`json:"email"`)
	if !errors.Is(err, errNoTag) {
		t.Fatalf("err = %v, want errNoTag", err)
	}
	_, err = parseTag(``)
	if !errors.Is(err, errNoTag) {
		t.Fatalf("err = %v, want errNoTag", err)
	}
}

func TestParseTagRefusals(t *testing.T) {
	cases := map[string]string{
		`stash:""`:                                         "names no verb",
		`stash:"email"`:                                    "names no verb",
		`stash:"email,encrypt,passthrough"`:                "not both",
		`stash:"id,passthrough,index=equality"`:            "passthrough field has no index",
		`stash:"email,encrypt,encrypt"`:                    "given twice",
		`stash:"email,encrypt,encrypt_into=TextEq"`:        "drop encrypt",
		`stash:"email,encrypt_into=TextEq,index=equality"`: "drop index=",
		`stash:"email,encrypt_into="`:                      "not a type name",
		`stash:"email,encrypt_into=eql.TextEq"`:            "not a type name",
		`stash:"email,shred"`:                              `unknown part "shred"`,
		`stash:"email,encrypt,index=fuzzy"`:                `unknown index "fuzzy"`,
		`stash:"email,encrypt,index="`:                     "names no index",
		`stash:"email,encrypt,index=equality;equality"`:    "given twice",
		`stash:"email,encrypt,index=match("`:               "( with no )",
		`stash:"email,encrypt,index=match)"`:               ") with no (",
		`stash:"email,encrypt,index=match()"`:              "empty options",
		`stash:"email,encrypt,index=match(=3)"`:            "not key or key=value",
		`stash:"email,encrypt,,"`:                          "an empty part",
		`stash:"context="`:                                 "names no context",
		`stash:"context=users,encrypt"`:                    "takes only opaque",
		`stash:"context=users,opaque,opaque"`:              "given twice",
		`stash:"email,opaque"`:                             "goes on the `_ struct{}` field",
		`stash:"email,context=users"`:                      "goes on the `_ struct{}` field",
		`stash:",encrypt"`:                                 "takes only passthrough",
		`stash:"a=b,encrypt"`:                              "is not a name",
	}
	for in, want := range cases {
		_, err := parseTag(in)
		if err == nil {
			t.Errorf("%s: want an error containing %q, got none", in, want)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q does not contain %q", in, err, want)
		}
	}
}

func TestSnakeCase(t *testing.T) {
	cases := map[string]string{
		"ID": "id", "CreatedAt": "created_at", "DeletedAt": "deleted_at", "MedicareNo": "medicare_no",
		"HTTPServer": "http_server", "UserID": "user_id", "Email": "email", "cache": "cache",
		"PhoneNumber": "phone_number", "A1B": "a1_b", "Internal": "internal",
	}
	for in, want := range cases {
		if got := snakeCase(in); got != want {
			t.Errorf("snakeCase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLowerFirst(t *testing.T) {
	cases := map[string]string{"User": "user", "ContactRow": "contactRow", "ID": "id", "HTTPServer": "httpServer", "Rows": "rows", "contactStash": "contactStash"}
	for in, want := range cases {
		if got := lowerFirst(in); got != want {
			t.Errorf("lowerFirst(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWrapComment(t *testing.T) {
	got := wrapComment("User prints its sealed fields in the clear: it has no String or LogValue method. Write them, or run stashgen with -redact.", 80)
	want := "// User prints its sealed fields in the clear: it has no String or LogValue\n// method. Write them, or run stashgen with -redact.\n"
	if got != want {
		t.Fatalf("wrapComment:\n%s\nwant:\n%s", got, want)
	}
}
