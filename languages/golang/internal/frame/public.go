package frame

import (
	"errors"
	"fmt"
	"reflect"
)

// Package encrypt declares the SDK's value types and its Encryptable
// interface, because a program names them there. Package encrypt imports
// this package, so this package cannot name those types. The functions below
// register those types with the codec.
//
// Each value type of the SDK is a distinct type with the same underlying
// type as a value type of this package. [Publish] registers one such pair.
// The codec then encodes a value of the SDK's type as the value type of this
// package. The codec decodes that value type as the SDK's type.
//
// [PublishEncryptable] registers the SDK's Encryptable interface. The codec
// declares no Encryptable interface. A type can write itself only through
// the published one.
//
// The init function of package encrypt calls both functions. No value of an
// SDK type can exist before that. Nothing calls them later, so the codec
// reads the tables without a lock.

var (
	// published maps each published type to the value type of this package
	// that the codec encodes it as.
	published = map[reflect.Type]reflect.Type{}
	// publicOf maps a value type of this package to the type it is published
	// as.
	publicOf = map[reflect.Type]reflect.Type{}
	// external is the published Encryptable interface, and a function that
	// calls its method with an Encoder. iface is nil until
	// [PublishEncryptable] sets it.
	external struct {
		iface reflect.Type
		call  func(v any, enc Encoder) error
	}
)

// publishable is the set of value types that [Publish] accepts as V.
var publishable = map[reflect.Type]bool{
	reflect.TypeFor[Date]():    true,
	reflect.TypeFor[Decimal](): true,
	reflect.TypeFor[Int128]():  true,
	reflect.TypeFor[Uint128](): true,
	reflect.TypeFor[UUID]():    true,
}

// Publish registers P as the public form of the value type V. The codec then
// encodes a P as a V, and decodes a V as a P. P must be a distinct type with
// the same underlying type as V.
//
// Publish panics in three cases:
//
//   - V is not a value type that can be published.
//   - P is V itself, or cannot be converted to V.
//   - P or V is already published with a different partner.
//
// Each case is a mistake in this module. A test of package encrypt finds it.
func Publish[P, V any]() {
	p, v := reflect.TypeFor[P](), reflect.TypeFor[V]()
	switch {
	case !publishable[v]:
		panic(fmt.Sprintf("frame: %s cannot be published", v))
	case p == v || p.Kind() != v.Kind() || !p.ConvertibleTo(v) || !v.ConvertibleTo(p):
		panic(fmt.Sprintf("frame: %s must be a distinct type with the same underlying type as %s", p, v))
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

// PublishEncryptable registers the interface I as the Encryptable interface.
// When a value implements I, the codec calls call, and the value writes
// itself. The codec uses reflection only for a value that does not implement
// I. PublishEncryptable panics if I is not an interface. PublishEncryptable
// also panics if a different interface is already published.
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

// internal converts v to the value type of this package when the type of v
// is a published one. Otherwise internal returns v unchanged.
func internal(v any) any {
	if v == nil {
		return nil
	}
	if t, ok := published[reflect.TypeOf(v)]; ok {
		return reflect.ValueOf(v).Convert(t).Interface()
	}
	return v
}

// internalValue converts rv to the value type of this package when the type
// of rv is a published one. Otherwise internalValue returns rv unchanged.
func internalValue(rv reflect.Value) reflect.Value {
	if !rv.IsValid() {
		return rv
	}
	if t, ok := published[rv.Type()]; ok {
		return rv.Convert(t)
	}
	return rv
}

// internalType returns the value type of this package that t is published
// for. For any other t, internalType returns t.
func internalType(t reflect.Type) reflect.Type {
	if v, ok := published[t]; ok {
		return v
	}
	return t
}

// public converts v, a value type of this package, to the type it is
// published as. The function returns v unchanged when the type of v is not
// published.
func public(v any) any {
	if t, ok := publicOf[reflect.TypeOf(v)]; ok {
		return reflect.ValueOf(v).Convert(t).Interface()
	}
	return v
}

// encryptableOf returns a function that makes v write itself, when v
// implements the published Encryptable interface. The function calls the
// EncryptValue method of v.
func encryptableOf(v any) (func(Encoder) error, bool) {
	if external.iface != nil && v != nil && reflect.TypeOf(v).Implements(external.iface) {
		return func(enc Encoder) error { return external.call(v, enc) }, true
	}
	return nil, false
}

// implementsEncryptable reports whether t implements the published
// Encryptable interface.
func implementsEncryptable(t reflect.Type) bool {
	return external.iface != nil && t.Implements(external.iface)
}

// Unpublished returns the value types that [Publish] accepts and that no
// call has published. The result is empty in a program that links package
// encrypt.
func Unpublished() []reflect.Type {
	var out []reflect.Type
	for t := range publishable {
		if _, ok := publicOf[t]; !ok {
			out = append(out, t)
		}
	}
	return out
}

// Usable reports whether e came from the codec. Only such an Encoder records
// what is written to it. The zero Encoder is not usable.
func (e Encoder) Usable() bool { return e.st != nil }

// Err returns the first error of the encode that e belongs to. For the zero
// Encoder, Err returns an error that says so.
func (e Encoder) Err() error {
	if e.st == nil {
		return errZeroEncoder
	}
	return e.st.err
}

var errZeroEncoder = errors.New("frame: the zero Encoder records nothing; use the Encoder that EncryptValue is given")
