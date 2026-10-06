// Package protosource reads the facts about a protobuf message's fields: each
// field's name, its Go name, its kind, and its options as annotations.
//
// A field option's key is the option's full name, such as
// "classification.data_categories", and its values are the option's values
// as strings. A policy matches on them with policy.Key.
package protosource

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
)

// New returns the source. The message given to policy.ForMessage must be a
// generated protobuf message, such as &pb.Individual{}.
func New() policy.Source { return source{} }

type source struct{}

// Facts reads the message's descriptor. It returns one fact for each field,
// in field-number order as the descriptor lists them.
func (source) Facts(message any) ([]policy.Fact, error) {
	m, ok := message.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("protosource: %T is not a protobuf message", message)
	}
	md := m.ProtoReflect().Descriptor()
	fields := md.Fields()
	facts := make([]policy.Fact, 0, fields.Len())
	for i := range fields.Len() {
		fd := fields.Get(i)
		facts = append(facts, policy.Fact{
			Message:     string(md.FullName()),
			Name:        string(fd.Name()),
			GoName:      GoName(string(fd.Name())),
			Kind:        fd.Kind().String(),
			Annotations: annotations(fd),
		})
	}
	return facts, nil
}

// annotations reads the extension fields set on the field's options.
func annotations(fd protoreflect.FieldDescriptor) []policy.Annotation {
	opts := fd.Options()
	if opts == nil {
		return nil
	}
	var out []policy.Annotation
	opts.ProtoReflect().Range(func(xd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if !xd.IsExtension() {
			return true
		}
		a := policy.Annotation{Key: string(xd.FullName())}
		if xd.IsList() {
			list := v.List()
			for j := range list.Len() {
				a.Values = append(a.Values, scalar(xd, list.Get(j)))
			}
		} else {
			a.Values = []string{scalar(xd, v)}
		}
		out = append(out, a)
		return true
	})
	return out
}

// scalar spells one option value: an enum by its name, everything else by
// its protoreflect string form.
func scalar(fd protoreflect.FieldDescriptor, v protoreflect.Value) string {
	if fd.Kind() == protoreflect.EnumKind {
		if ev := fd.Enum().Values().ByNumber(v.Enum()); ev != nil {
			return string(ev.Name())
		}
	}
	return v.String()
}

// GoName is the Go field name protoc-gen-go gives a proto field: the first
// letter capitalised, and an underscore before a lower-case letter dropped
// with that letter capitalised. medicare_no becomes MedicareNo; foo_1bar
// keeps its underscore, as protoc-gen-go does.
func GoName(protoName string) string {
	var b strings.Builder
	upper := true
	for i := 0; i < len(protoName); i++ {
		c := protoName[i]
		switch {
		case c == '_' && i+1 < len(protoName) && protoName[i+1] >= 'a' && protoName[i+1] <= 'z':
			upper = true
		case c == '.':
			b.WriteByte('_')
		case upper && c >= 'a' && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
			upper = false
		default:
			b.WriteByte(c)
			upper = false
		}
	}
	return b.String()
}
