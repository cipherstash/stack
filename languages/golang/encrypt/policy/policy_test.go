package policy

import (
	"strings"
	"testing"
)

var category = Key("classification.data_categories")

func fact(name, kind string, categories ...string) Fact {
	f := Fact{Message: "individuals.Individual", Name: name, GoName: strings.ToUpper(name[:1]) + name[1:], Kind: kind}
	if len(categories) > 0 {
		f.Annotations = []Annotation{{Key: string(category), Values: categories}}
	}
	return f
}

var base = FirstOf(
	When(category.Under("user.government_id"), EncryptInto("TextEq")),
	When(category.Under("user.contact.email"), EncryptIndex(Equality, Match())),
	When(category.Under("user"), Encrypt()),
)

var individuals = ForMessage(nil, Context("individuals"),
	FirstOf(
		When(Field("medicare_no"), EncryptInto("TextEq"), Name("medicare_number")),
		When(Field("id"), Passthrough()),
		When(Field("nickname"), Passthrough()),
	).OrElse(base),
)

func TestTheFirstMatchingRuleDecides(t *testing.T) {
	cases := []struct {
		f    Fact
		want string // the field's tag
	}{
		{fact("id", "int64"), "id,passthrough"},
		{fact("name", "string", "user.name"), "name,encrypt"},
		{fact("email", "string", "user.contact.email"), "email,encrypt,index=equality;match"},
		{fact("medicare_no", "string", "user.government_id"), "medicare_number,encrypt_into=TextEq"},
		{fact("nickname", "string"), "nickname,passthrough"},
	}
	for _, c := range cases {
		o, ok := individuals.Decide(c.f)
		if !ok {
			t.Errorf("%s: no rule decides it", c.f)
			continue
		}
		got, ok := o.Tag(c.f.Name)
		if !ok {
			t.Errorf("%s: refused: %s", c.f, o.Reason())
			continue
		}
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.f, got, c.want)
		}
	}
	if individuals.Context() != "individuals" {
		t.Errorf("Context = %q", individuals.Context())
	}
}

func TestAFieldNoRuleDecidesIsReported(t *testing.T) {
	f := fact("shoe_size", "int32", "system.operations")
	if _, ok := individuals.Decide(f); ok {
		t.Fatal("a field outside every rule was decided")
	}
	if got := f.String(); got != "individuals.Individual.shoe_size (int32; classification.data_categories = system.operations)" {
		t.Fatalf("String = %q", got)
	}
}

func TestUnderMatchesTheCategoryAndItsChildrenOnly(t *testing.T) {
	m := category.Under("user")
	if !m.Match(fact("a", "string", "user")) || !m.Match(fact("a", "string", "user.contact.email")) {
		t.Fatal("Under does not match the category or a child")
	}
	if m.Match(fact("a", "string", "username")) || m.Match(fact("a", "string")) {
		t.Fatal("Under matches a sibling or a field with no category")
	}
	if !category.Is("user").Match(fact("a", "string", "user")) || category.Is("user").Match(fact("a", "string", "user.name")) {
		t.Fatal("Is does not match exactly")
	}
}

func TestOtherwiseFailAndIdentity(t *testing.T) {
	rules := FirstOf(
		When(Field("secret"), Fail("never store this field")),
		When(Field("old"), Encrypt(), Name("renamed"), Identity("old")),
	).OrElse(Otherwise(Omit()))
	o, ok := rules.Decide(fact("secret", "string"))
	if !ok || o.Reason() != "never store this field" {
		t.Fatalf("Fail: ok=%v reason=%q", ok, o.Reason())
	}
	if _, ok := o.Tag("secret"); ok {
		t.Fatal("a Fail outcome gave a tag")
	}
	o, _ = rules.Decide(fact("old", "string"))
	if tag, _ := o.Tag("old"); tag != "renamed,encrypt" || o.Identity != "old" {
		t.Fatalf("Name and Identity: %q %q", tag, o.Identity)
	}
	o, ok = rules.Decide(fact("anything", "bytes"))
	if tag, _ := o.Tag("anything"); !ok || tag != "-" {
		t.Fatalf("Otherwise: ok=%v tag=%q", ok, tag)
	}
	if tag, _ := EncryptIndex(Equality, Match(IndexOption{"k", "3"}), Ore, Ope).apply("x"); tag != "x,encrypt,index=equality;match(k=3);ore;ope" {
		t.Fatalf("indexes spell as %q", tag)
	}
	if tag, _ := Index(JSON(IndexOption{Key: "compat"})).apply("attrs"); tag != "attrs,index=json(compat)" {
		t.Fatalf("json spells as %q", tag)
	}
	var none Rules
	if _, ok := none.Decide(fact("x", "string")); ok {
		t.Fatal("empty rules decided a field")
	}
	if _, ok := ForMessage(nil, "c", nil).Decide(fact("x", "string")); ok {
		t.Fatal("a message with no rules decided a field")
	}
}

// apply is Outcome.Tag for a bare decision.
func (d Decision) apply(name string) (string, bool) { return Outcome{Decision: d}.Tag(name) }
