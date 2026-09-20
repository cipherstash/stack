package main

import "testing"

// The id is a path component, and the file it is read from is writable by
// anything on the machine, so the rule is the Rust reader's exactly.
func TestValidWorkspaceIDIsStackProfilesRule(t *testing.T) {
	valid := []string{"ABCDEFGHIJKLMNOP", "A2B3C4D5E6F7G2H3", "2222222222222222"}
	for _, id := range valid {
		if !validWorkspaceID(id) {
			t.Errorf("%q is sixteen base32 characters and must be accepted", id)
		}
	}
	invalid := map[string]string{
		"":                   "empty",
		"ABCDEFGHIJKLMNO":    "fifteen characters",
		"ABCDEFGHIJKLMNOPQ":  "seventeen characters",
		"abcdefghijklmnop":   "lower case",
		"ABCDEFGHIJKLMN01":   "digits outside 2-7",
		"../../../../../etc": "a path",
		"ABCDEFG/IJKLMNOP":   "a separator inside sixteen characters",
		"ABCDEFGHIJKLMNO\n":  "a trailing newline",
	}
	for id, why := range invalid {
		if validWorkspaceID(id) {
			t.Errorf("%q (%s) must be refused", id, why)
		}
	}
}
