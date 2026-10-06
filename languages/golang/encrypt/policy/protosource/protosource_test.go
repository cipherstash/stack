package protosource

import (
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
	"github.com/cipherstash/stack/languages/golang/encrypt/policy/protosource/internal/testpb"
)

func TestFactsReadTheDescriptorAndItsOptions(t *testing.T) {
	facts, err := New().Facts(&testpb.Individual{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"individuals.Individual.id (int64)",
		"individuals.Individual.name (string; classification.data_categories = user.name)",
		"individuals.Individual.email (string; classification.data_categories = user.contact.email)",
		"individuals.Individual.medicare_no (string; classification.data_categories = user.government_id)",
		"individuals.Individual.nickname (string)",
	}
	if len(facts) != len(want) {
		t.Fatalf("%d facts, want %d", len(facts), len(want))
	}
	for i, f := range facts {
		if f.String() != want[i] {
			t.Errorf("fact %d = %q, want %q", i, f, want[i])
		}
	}
	if facts[3].GoName != "MedicareNo" || facts[0].GoName != "Id" {
		t.Errorf("GoName: %q %q", facts[0].GoName, facts[3].GoName)
	}
	if got := facts[2].Values("classification.data_categories"); len(got) != 1 || got[0] != "user.contact.email" {
		t.Errorf("Values = %q", got)
	}
}

func TestTheRulesRunOnRealFacts(t *testing.T) {
	category := policy.Key("classification.data_categories")
	rules := policy.FirstOf(
		policy.When(category.Under("user.government_id"), policy.EncryptInto("TextEq")),
		policy.When(category.Under("user.contact.email"), policy.EncryptIndex(policy.Equality, policy.Match())),
		policy.When(category.Under("user"), policy.Encrypt()),
	)
	facts, _ := New().Facts(&testpb.Individual{})
	want := map[string]string{"name": "name,encrypt", "email": "email,encrypt,index=equality;match", "medicare_no": "medicare_no,encrypt_into=TextEq"}
	for _, f := range facts {
		o, ok := rules.Decide(f)
		tag, _ := o.Tag(f.Name)
		if w, decided := want[f.Name]; decided != ok || tag != w {
			t.Errorf("%s: ok=%v tag=%q, want %q", f.Name, ok, tag, w)
		}
	}
}

func TestNotAMessage(t *testing.T) {
	_, err := New().Facts(struct{}{})
	if err == nil || !strings.Contains(err.Error(), "not a protobuf message") {
		t.Fatalf("err = %v", err)
	}
}

func TestGoName(t *testing.T) {
	cases := map[string]string{"id": "Id", "medicare_no": "MedicareNo", "foo_1bar": "Foo_1bar", "Already": "Already", "a_b_c": "ABC", "x__y": "X_Y"}
	for in, want := range cases {
		if got := GoName(in); got != want {
			t.Errorf("GoName(%q) = %q, want %q", in, got, want)
		}
	}
}
