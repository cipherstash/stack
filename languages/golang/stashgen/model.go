package stashgen

import (
	"fmt"
	"go/types"
	"strings"
)

// ModelRequest is one -model flag: a struct with one field for each column,
// for separate columns.
type ModelRequest struct {
	// Name is the suffix of the generated functions: EncryptName, DecryptName.
	Name string
	// Type is the model struct, in this package or as P.T.
	Type string
	// Declares is a struct in this package that carries the tags for a Type
	// that cannot, or "".
	Declares string
}

// ParseModelFlag reads a -model flag: Name=R or Name=R:D.
func ParseModelFlag(s string) (ModelRequest, error) {
	name, rest, ok := strings.Cut(s, "=")
	if !ok || name == "" || rest == "" {
		return ModelRequest{}, fmt.Errorf("stashgen: -model %q is not Name=R or Name=R:D", s)
	}
	if !isIdent(name) || strings.ToUpper(name[:1]) != name[:1] {
		return ModelRequest{}, fmt.Errorf("stashgen: -model %q: %q must be an exported Go name", s, name)
	}
	typ, declares, _ := strings.Cut(rest, ":")
	if typ == "" || (strings.Contains(rest, ":") && declares == "") {
		return ModelRequest{}, fmt.Errorf("stashgen: -model %q is not Name=R or Name=R:D", s)
	}
	return ModelRequest{Name: name, Type: typ, Declares: declares}, nil
}

// readModel binds a model's fields to the declaration's outputs.
func (r *reader) readModel(m ModelRequest) error {
	f := r.file
	if f.decl.Opaque {
		return fmt.Errorf("stashgen: -model %s: an opaque struct has one output and needs no model", m.Name)
	}
	modelNamed, modelStruct, err := r.lookupAny(m.Type)
	if err != nil {
		return err
	}
	if hasUnexported(modelStruct) && modelNamed.Obj().Pkg().Path() != r.pkg.PkgPath {
		return fmt.Errorf("stashgen: -model %s: %s has an unexported field, so Go cannot convert it to a copy of its fields", m.Name, m.Type)
	}
	tagStruct := modelStruct
	tagType := m.Type
	if m.Declares != "" {
		var declNamed *types.Named
		declNamed, tagStruct, err = lookupStruct(r.pkg, m.Declares)
		if err != nil {
			return err
		}
		_ = declNamed
		tagType = m.Declares
		if err := matchFields(tagType, tagStruct, m.Type, modelStruct, r.typeExpr); err != nil {
			return err
		}
	}
	tagsByName := map[string]string{}
	for i := range tagStruct.NumFields() {
		tagsByName[tagStruct.Field(i).Name()] = tagStruct.Tag(i)
	}

	gm := genModel{
		name:      m.Name,
		typeExpr:  r.typeExpr(modelNamed),
		shapeName: lowerFirst(m.Name) + "Shape",
		codecVar:  lowerFirst(m.Name) + "Codec",
		encryptFn: "Encrypt" + m.Name,
		decryptFn: "Decrypt" + m.Name,
		paramName: lowerFirst(m.Name),
	}
	if f.fieldTypePrefix != "" {
		gm.shapeName = lowerFirst(f.fieldTypePrefix) + m.Name + "Shape"
		gm.codecVar = lowerFirst(f.fieldTypePrefix) + m.Name + "Codec"
	}
	if gm.paramName == f.paramName || gm.paramName == "ctx" || gm.paramName == "d" || goKeywords[gm.paramName] {
		gm.paramName = "models"
	}

	bound := map[string]bool{} // "email" or "email,equality"
	for i := range modelStruct.NumFields() {
		fld := modelStruct.Field(i)
		if fld.Name() == "_" {
			return fmt.Errorf("stashgen: -model %s: %s has a `_` field, which cannot be a column", m.Name, m.Type)
		}
		mf := modelField{name: fld.Name(), typeExpr: r.typeExpr(fld.Type())}
		raw, ok := tagsByName[fld.Name()]
		t, err := parseModelTag(raw)
		if !ok || err == errNoTag {
			return fieldErr(tagType, fld.Name(), "no stash tag; each field of a model names one output, `stash:\"email\"` or `stash:\"email,equality\"`, or `stash:\"-\"`")
		}
		if err != nil {
			return fieldErr(tagType, fld.Name(), "%v", err)
		}
		if t.omit {
			gm.fields = append(gm.fields, mf)
			continue
		}
		if fld.Embedded() {
			return fieldErr(tagType, fld.Name(), "a model's embedded struct is one column per field, which it cannot name; tag it `stash:\"-\"`")
		}
		key := t.field
		if t.index != "" {
			key += "," + string(t.index)
		}
		if bound[key] {
			return fieldErr(tagType, fld.Name(), "the output %q is already bound to another field", key)
		}
		bound[key] = true
		g, out := f.lookupOutput(t.field, t.index)
		if g == nil {
			return fieldErr(tagType, fld.Name(), "%s declares no field named %q", f.typeName, t.field)
		}
		if out == nil {
			if t.index == "" {
				return fieldErr(tagType, fld.Name(), "field %q has no ciphertext; it has only indexes", t.field)
			}
			return fieldErr(tagType, fld.Name(), "field %q has no %s index", t.field, t.index)
		}
		if got := pathType(fld.Type()); got != out.pathType {
			return fieldErr(tagType, fld.Name(), "has type %s, and the %s of %q is %s", r.typeExpr(fld.Type()), outputWord(g, out), t.field, out.typeExpr)
		}
		mf.field, mf.output = g, out
		mf.source = sourceExpr("e", g, out)
		gm.fields = append(gm.fields, mf)
	}
	for _, g := range f.fields {
		for i := range g.outputs {
			out := &g.outputs[i]
			key := g.Name
			if out.index != "" {
				key += "," + string(out.index)
			}
			if !bound[key] {
				return fieldErr(tagType, "", "no field for the %s of %q", outputWord(&g, out), g.Name)
			}
		}
	}
	f.models = append(f.models, gm)
	return nil
}

func outputWord(g *genField, out *output) string {
	switch {
	case out.index != "":
		return string(out.index) + " term"
	case g.Stored():
		return "value"
	case g.Verb == VerbEncryptInto:
		return "EQL value"
	}
	return "ciphertext"
}

// sourceExpr is the expression that reads one output from the encrypted value e.
func sourceExpr(e string, g *genField, out *output) string {
	switch g.Verb {
	case VerbPassthrough, VerbContextField, VerbEncryptInto:
		return e + "." + g.GoName
	}
	return e + "." + g.GoName + "." + out.name
}

func (f *genFile) lookupOutput(name string, index IndexName) (*genField, *output) {
	for i := range f.fields {
		g := &f.fields[i]
		if g.Name != name {
			continue
		}
		for j := range g.outputs {
			out := &g.outputs[j]
			if out.index == index && (index != "" || out.name != "") {
				if index == "" && out.index != "" {
					continue
				}
				return g, out
			}
		}
		return g, nil
	}
	return nil, nil
}

type modelTag struct {
	omit  bool
	field string
	index IndexName
}

// parseModelTag reads `email`, `email,equality` or `-`.
func parseModelTag(raw string) (modelTag, error) {
	value, ok := lookupTag(raw, tagKey)
	if !ok {
		return modelTag{}, errNoTag
	}
	if value == "-" {
		return modelTag{omit: true}, nil
	}
	name, index, hasIndex := strings.Cut(value, ",")
	if name == "" || strings.ContainsAny(name, "=();") {
		return modelTag{}, fmt.Errorf("tag %q: the first part names a field of the declaration", value)
	}
	t := modelTag{field: name}
	if hasIndex {
		if !knownIndex(IndexName(index)) {
			return modelTag{}, fmt.Errorf("tag %q: %q is not an index; the indexes are equality, match, ore, ope and json", value, index)
		}
		t.index = IndexName(index)
	}
	return t, nil
}

// lookupAny resolves a type name in this package, or P.T through its imports.
func (r *reader) lookupAny(name string) (*types.Named, *types.Struct, error) {
	if strings.Contains(name, ".") {
		return lookupQualified(r.pkg, name)
	}
	return lookupStruct(r.pkg, name)
}

// matchFields checks that a declaring struct names every exported field of
// the struct it declares for, with the same types.
func matchFields(declName string, decl *types.Struct, forName string, target *types.Struct, typeExpr func(types.Type) string) error {
	byName := map[string]*types.Var{}
	for i := range target.NumFields() {
		byName[target.Field(i).Name()] = target.Field(i)
	}
	named := map[string]bool{}
	for i := range decl.NumFields() {
		df := decl.Field(i)
		tf, ok := byName[df.Name()]
		if !ok {
			return fieldErr(declName, df.Name(), "%s has no field %s", forName, df.Name())
		}
		if !types.Identical(tf.Type(), df.Type()) {
			return fieldErr(declName, df.Name(), "has type %s, and %s.%s has type %s", typeExpr(df.Type()), forName, df.Name(), typeExpr(tf.Type()))
		}
		named[df.Name()] = true
	}
	for i := range target.NumFields() {
		tf := target.Field(i)
		if tf.Exported() && !named[tf.Name()] {
			return fieldErr(forName, tf.Name(), "not named by %s; every exported field of %s needs a tag there", declName, forName)
		}
	}
	return nil
}
