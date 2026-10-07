// Package protosource reads the facts about a protobuf message's fields: each
// field's name, its Go name, its kind, and its options as annotations.
//
// A field option's key is the option's full name, such as
// "classification.data_categories", and its values are the option's values
// as strings. A policy matches on them with policy.Key.
package protosource

import (
	"fmt"

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
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() {
			// protoc-gen-go puts a oneof's members in wrapper types behind
			// one interface field, so the struct has no field for them.
			return nil, fmt.Errorf("protosource: %s: field %s is in the oneof %s, and a oneof cannot be generated", md.FullName(), fd.Name(), od.Name())
		}
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

// GoName is the Go field name protoc-gen-go gives a proto field: its
// GoCamelCase, word for word. A word starts at an underscore or a capital;
// a digit is a word of its own, so the letter after it starts a new word
// (foo_1bar is Foo_1Bar, sha256sum is Sha256Sum); an underscore before a
// lower-case letter is dropped and the letter capitalised; a leading
// underscore becomes X (_x is XX); a dot becomes an underscore.
func GoName(protoName string) string {
	var b []byte
	for i := 0; i < len(protoName); i++ {
		c := protoName[i]
		switch {
		case c == '.' && i+1 < len(protoName) && isASCIILower(protoName[i+1]):
			// Skip over '.' in ".{{lowercase}}".
		case c == '.':
			b = append(b, '_')
		case c == '_' && (i == 0 || protoName[i-1] == '.'):
			// An initial '_' (or one after '.') becomes 'X', so the name
			// starts with a capital.
			b = append(b, 'X')
		case c == '_' && i+1 < len(protoName) && isASCIILower(protoName[i+1]):
			// Skip over '_' in "_{{lowercase}}".
		case c >= '0' && c <= '9':
			b = append(b, c)
		default:
			// A letter starts a word, capitalised; the lower-case run after
			// it is the rest of the word.
			if isASCIILower(c) {
				c -= 'a' - 'A'
			}
			b = append(b, c)
			for ; i+1 < len(protoName) && isASCIILower(protoName[i+1]); i++ {
				b = append(b, protoName[i+1])
			}
		}
	}
	return string(b)
}

func isASCIILower(c byte) bool { return 'a' <= c && c <= 'z' }
