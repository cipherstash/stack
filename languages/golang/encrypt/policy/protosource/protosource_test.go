package protosource

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

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
	// protoc-gen-go's GoCamelCase, including the cases a reviewer found the
	// first version wrong on: a digit ends a word, a leading underscore is X.
	cases := map[string]string{
		"id": "Id", "medicare_no": "MedicareNo", "foo_1bar": "Foo_1Bar", "sha256sum": "Sha256Sum", "_x": "XX",
		"Already": "Already", "a_b_c": "ABC", "x__y": "X_Y", "a.b": "AB", "a.B": "A_B", "x_Y": "X_Y", "ab1": "Ab1",
	}
	for in, want := range cases {
		if got := GoName(in); got != want {
			t.Errorf("GoName(%q) = %q, want %q", in, got, want)
		}
	}
}

// scalar spells an enum option by its value name: a dynamic enum field
// stands in for a generated one, since testpb declares no enum.
func TestScalarSpellsAnEnumByName(t *testing.T) {
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("enum_test.proto"),
		Package: proto.String("enumtest"),
		Syntax:  proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Level"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("LEVEL_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("LEVEL_HIGH"), Number: proto.Int32(2)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Holder"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name: proto.String("level"), Number: proto.Int32(1),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(),
				TypeName: proto.String(".enumtest.Level"),
				JsonName: proto.String("level"),
			}},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fd := file.Messages().Get(0).Fields().Get(0)
	if got := scalar(fd, protoreflect.ValueOfEnum(2)); got != "LEVEL_HIGH" {
		t.Fatalf("scalar(enum 2) = %q, want LEVEL_HIGH", got)
	}
	// A number with no name falls back to the number.
	if got := scalar(fd, protoreflect.ValueOfEnum(7)); got != "7" {
		t.Fatalf("scalar(enum 7) = %q", got)
	}
}
