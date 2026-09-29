package factstest_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/factstest"
	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt/plan"
)

func TestStructTags(t *testing.T) {
	type embedded struct{ Inner string }
	type row struct {
		embedded
		ID     *int64
		Email  string `facts:"a=x,y;b=z"`
		hidden string //nolint:unused // proves untagged unexported fields are skipped
	}
	facts, err := factstest.StructTags.Facts(&row{})
	if err != nil {
		t.Fatal(err)
	}
	want := []plan.Fact{
		{Message: "factstest_test.row", Field: "id", GoField: "ID", Kind: "int64"},
		{Message: "factstest_test.row", Field: "email", GoField: "Email", Kind: "string", Annotations: []plan.Annotation{
			{Key: "a", Values: []string{"x", "y"}}, {Key: "b", Values: []string{"z"}},
		}},
	}
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("facts =\n%+v\nwant\n%+v", facts, want)
	}
	if got := facts[1].String(); got != "factstest_test.row.email (Email) [a=x,y; b=z]" {
		t.Errorf("String = %s", got)
	}
	type taggedInner struct {
		Secret string `facts:"a=x"`
	}
	type deeper struct{ taggedInner }
	for name, bad := range map[string]struct {
		msg any
		say string
	}{
		"not a struct": {42, "reads structs"},
		"nil":          {nil, "reads structs"},
		"no value": {struct {
			A string `facts:"a="`
		}{}, "key=value"},
		"no key": {struct {
			A string `facts:"=x"`
		}{}, "key=value"},
		"empty value": {struct {
			A string `facts:"a=x,"`
		}{}, "empty value"},
		"key twice": {struct {
			A string `facts:"a=x;a=y"`
		}{}, "given twice"},
		// A tag the plan cannot bind is refused, never quietly plaintext.
		"tagged unexported field": {struct {
			medicareNo string `facts:"a=x"` //nolint:unused // the tag is the point
		}{}, "unexported field"},
		"tagged embedded field": {struct {
			embedded `facts:"a=x"`
		}{}, "embedded field"},
		"tag inside an embedded struct": {struct{ taggedInner }{}, "Secret"},
		"tag two embeddings deep":       {struct{ deeper }{}, "taggedInner.Secret"},
	} {
		_, err := factstest.StructTags.Facts(bad.msg)
		if err == nil {
			t.Errorf("%s: facts read", name)
		} else if !strings.Contains(err.Error(), bad.say) {
			t.Errorf("%s: err = %q, want it to say %q", name, err, bad.say)
		}
	}
	// The schema spelling of a Go field name.
	type spelled struct {
		ID         int64
		Email      string
		HTTPPort   int
		MedicareNo string
		Line2      string
		UserID     string
		OAuth2Key  string
	}
	got, err := factstest.StructTags.Facts(spelled{})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(got))
	for i, f := range got {
		names[i] = f.Field
	}
	if want := []string{"id", "email", "http_port", "medicare_no", "line2", "user_id", "o_auth2_key"}; !reflect.DeepEqual(names, want) {
		t.Errorf("schema names = %v, want %v", names, want)
	}
}
