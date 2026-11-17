package stashgen

import (
	"go/types"
	"testing"
)

// With GOEXPERIMENT=jsonv2, the default from Go 1.27, json.RawMessage is an
// alias of jsontext.Value. An alias of it then names encoding/json's
// RawMessage only partway along its alias chain, and is still the type
// itself. The types are built here, so the test does not depend on the
// toolchain's encoding/json.
func TestValueKindFindsRawMessageAlongAnAliasChain(t *testing.T) {
	jsonPkg := types.NewPackage("encoding/json", "json")
	users := types.NewPackage("example.com/users", "users")
	bytes := types.NewSlice(types.Typ[types.Byte])
	value := types.NewNamed(types.NewTypeName(0, types.NewPackage("encoding/json/jsontext", "jsontext"), "Value", nil), bytes, nil)

	v2Raw := types.NewAlias(types.NewTypeName(0, jsonPkg, "RawMessage", nil), value)
	v1Raw := types.NewNamed(types.NewTypeName(0, jsonPkg, "RawMessage", nil), bytes, nil)
	aliasOf := func(name string, rhs types.Type) types.Type {
		return types.NewAlias(types.NewTypeName(0, users, name, nil), rhs)
	}

	for _, c := range []struct {
		name string
		t    types.Type
		want bool
	}{
		{"jsonv2 RawMessage", v2Raw, true},
		{"alias of jsonv2 RawMessage", aliasOf("DocAlias", v2Raw), true},
		{"alias of an alias of jsonv2 RawMessage", aliasOf("Outer", aliasOf("DocAlias", v2Raw)), true},
		{"alias of v1 RawMessage", aliasOf("DocAlias", v1Raw), true},
		{"jsontext.Value", value, false},
		{"a type defined over RawMessage", types.NewNamed(types.NewTypeName(0, users, "Doc", nil), v1Raw.Underlying(), nil), false},
	} {
		kind, ok := valueKind(c.t)
		if got := ok && kind == KindJSON; got != c.want {
			t.Errorf("%s: valueKind = %q, %v; want json %v", c.name, kind, ok, c.want)
		}
	}
}
