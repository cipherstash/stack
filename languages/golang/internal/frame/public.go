package frame

import (
	"errors"
	"fmt"
	"reflect"
)

// The SDK's value types and its Encryptable are declared in package encrypt,
// where a program names them, and encrypt imports this package, so the codec
// cannot name them. Each SDK value type is a type of its own over the same
// underlying type as one of the value types here. Publish tells the codec
// about it: the codec writes a value of the SDK's type as the value type
// here, and decodes that value type as the SDK's. PublishEncryptable does the
// same for the SDK's Encryptable.
//
// The codec has no Encryptable of its own: the published one is the only
// interface a type writes itself through.
//
// Both are called from package encrypt's init function, before any value of
// an SDK type can exist, and never after. The tables are read without a lock.

var (
	// published maps a published type to the value type here it stands for.
	published = map[reflect.Type]reflect.Type{}
	// publicOf maps a value type here to the type it is published as.
	publicOf = map[reflect.Type]reflect.Type{}
	// external is the SDK's Encryptable, and how to call its method with
	// an Encoder; iface is nil until it is published.
	external struct {
		iface reflect.Type
		call  func(v any, enc Encoder) error
	}
)

// publishable are the value types the SDK may publish a type of its own for.
var publishable = map[reflect.Type]bool{
	reflect.TypeFor[Date]():    true,
	reflect.TypeFor[Decimal](): true,
	reflect.TypeFor[Int128]():  true,
	reflect.TypeFor[Uint128](): true,
	reflect.TypeFor[UUID]():    true,
}

// Publish makes P the type the codec reads as V and decodes V as. P must be
// a type of its own over V's underlying type. It panics if V cannot be
// published, if P is not convertible to V, or if either is already
// published as something else: each is a mistake in the module, which a
// test of package encrypt finds.
func Publish[P, V any]() {
	p, v := reflect.TypeFor[P](), reflect.TypeFor[V]()
	switch {
	case !publishable[v]:
		panic(fmt.Sprintf("frame: %s cannot be published", v))
	case p == v || p.Kind() != v.Kind() || !p.ConvertibleTo(v) || !v.ConvertibleTo(p):
		panic(fmt.Sprintf("frame: %s is not a type of its own over %s's underlying type", p, v))
	}
	if old, ok := published[p]; ok && old != v {
		panic(fmt.Sprintf("frame: %s is already published as %s", p, old))
	}
	if old, ok := publicOf[v]; ok && old != p {
		panic(fmt.Sprintf("frame: %s is already published as %s", v, old))
	}
	published[p] = v
	publicOf[v] = p
}

// PublishEncryptable makes I, an interface, the Encryptable: the codec asks a
// value that implements I to write itself with call, before it falls back to
// reflection. It panics if I is not an interface, or if another interface
// is already published.
func PublishEncryptable[I any](call func(v I, enc Encoder) error) {
	iface := reflect.TypeFor[I]()
	if iface.Kind() != reflect.Interface {
		panic(fmt.Sprintf("frame: %s is not an interface", iface))
	}
	if external.iface != nil && external.iface != iface {
		panic(fmt.Sprintf("frame: %s is already published as Encryptable", external.iface))
	}
	external.iface = iface
	external.call = func(v any, enc Encoder) error { return call(v.(I), enc) }
}

// internal is v as the value type here when v's type is a published one,
// and v unchanged otherwise.
func internal(v any) any {
	if v == nil {
		return nil
	}
	if t, ok := published[reflect.TypeOf(v)]; ok {
		return reflect.ValueOf(v).Convert(t).Interface()
	}
	return v
}

// internalValue is rv converted to the value type here when its type is a
// published one, and rv unchanged otherwise.
func internalValue(rv reflect.Value) reflect.Value {
	if !rv.IsValid() {
		return rv
	}
	if t, ok := published[rv.Type()]; ok {
		return rv.Convert(t)
	}
	return rv
}

// internalType is the value type here that t stands for, or t.
func internalType(t reflect.Type) reflect.Type {
	if v, ok := published[t]; ok {
		return v
	}
	return t
}

// public is v, a value type here, as the type it is published as, or v
// unchanged when it is not published.
func public(v any) any {
	if t, ok := publicOf[reflect.TypeOf(v)]; ok {
		return reflect.ValueOf(v).Convert(t).Interface()
	}
	return v
}

// encryptableOf is how v writes itself: its EncryptValue, when v
// implements the published Encryptable.
func encryptableOf(v any) (func(Encoder) error, bool) {
	if external.iface != nil && v != nil && reflect.TypeOf(v).Implements(external.iface) {
		return func(enc Encoder) error { return external.call(v, enc) }, true
	}
	return nil, false
}

// implementsEncryptable reports whether t implements the published
// Encryptable.
func implementsEncryptable(t reflect.Type) bool {
	return external.iface != nil && t.Implements(external.iface)
}

// Unpublished is every value type that may be published and is not: a
// program that links package encrypt has none.
func Unpublished() []reflect.Type {
	var out []reflect.Type
	for t := range publishable {
		if _, ok := publicOf[t]; !ok {
			out = append(out, t)
		}
	}
	return out
}

// Usable reports whether e is an Encoder the codec handed out, which
// records what is written to it. The zero Encoder is not.
func (e Encoder) Usable() bool { return e.st != nil }

// Err is the first error of the encode e writes to, or an error saying e is
// the zero Encoder.
func (e Encoder) Err() error {
	if e.st == nil {
		return errZeroEncoder
	}
	return e.st.err
}

var errZeroEncoder = errors.New("frame: the zero Encoder writes nothing; use the one EncryptValue is given")
