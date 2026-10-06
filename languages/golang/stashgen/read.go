package stashgen

import (
	"fmt"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// The import paths of the SDK packages generated code names.
const (
	encryptPath    = "github.com/cipherstash/stack/languages/golang/encrypt"
	eqlPath        = encryptPath + "/eql"
	gensupportPath = encryptPath + "/gensupport"
)

// genFile is everything the emitter needs for one generated file. The reader
// builds it from the package's types; the emitter turns it into Go source.
type genFile struct {
	pkgName string
	imports *importSet

	// The plaintext type.
	typeName  string // how messages and TypeName print it: "User", "crm.Contact"
	typeExpr  string // the Go type the functions take: "User", "crm.Contact", "*pb.Individual"
	zeroExpr  string // "User{}", or "nil" for a pointer
	isPointer bool

	// The shape check, or none when the type has an unexported field in
	// another package and so cannot convert.
	shapeName   string
	shapeSource string // "User{}", "crm.Contact{}"
	shapeFields []shapeField

	// Generated names.
	encName         string // "EncryptedUser"
	declVar         string // "declaration"
	codecVar        string // "codec"
	fieldsVar       string // "Fields"
	fieldTypePrefix string // "" or the -name
	encryptFn       string
	decryptFn       string
	paramName       string // the slice parameter of Encrypt

	notices         []string
	printsPlaintext bool
	unexported      []string
	redact          bool
	redactRecv      string

	decl    Declaration
	members []encMember // the fields of the encrypted type
	fields  []genField  // every stored field, in declared order
	opaque  []genField  // the fields of an opaque struct
	models  []genModel
}

// shapeField is one field of the shape struct, which mirrors the plaintext
// struct field for field.
type shapeField struct {
	embedded bool
	name     string
	typeExpr string
}

// encMember is one member of the encrypted struct: a field, or an embedded
// struct carried through from the plaintext type.
type encMember struct {
	embedded bool
	name     string
	typeExpr string
	tags     string // the other libraries' tags, without stash
}

// genField is one stored field with what the emitter writes for it.
type genField struct {
	Field
	typeExpr   string   // the field's Go type
	via        string   // the embedded passthrough struct it is promoted from, or ""
	tags       string   // the other libraries' tags, without stash
	outputType string   // the encrypted type's field type: "eql.TextEq" or "EncryptedContactEmail"
	outputs    []output // the outputs of a sealed field in separate columns
	queryType  string   // "eql.TextEqQuery", or "" when the field has no query
	fieldType  string   // "EmailField"
	pathType   string   // the type with its package path, for model checks
}

// output is one output of a sealed field in separate columns.
type output struct {
	name     string // "Ciphertext", "Equality"
	typeExpr string // "encrypt.Ciphertext"
	pathType string
	index    IndexName // "" for the ciphertext
}

// genModel is one -model flag.
type genModel struct {
	name      string // "Rows"
	typeExpr  string // "ContactRow"
	shapeName string // "rowsShape"
	codecVar  string // "rowsCodec"
	encryptFn string
	decryptFn string
	paramName string
	fields    []modelField
}

// modelField is one field of a model, bound to one output of the declaration.
type modelField struct {
	name     string // the model's field name
	typeExpr string
	source   string // the expression on the encrypted value, or "" for a field left zero
	// For the reverse direction.
	field  *genField
	output *output
}

// reader builds a genFile from a loaded package.
type reader struct {
	pkg     *packages.Package
	req     Request
	eql     []EQLType
	file    *genFile
	imports *importSet
	// The package the file is written into, when it is not pkg: the policy
	// path writes into a package of the user's own.
	outPkgName string
	outPkgPath string
}

func (r *reader) qualifier(p *types.Package) string {
	if p == nil || p.Path() == r.outPath() {
		return ""
	}
	return r.imports.add(p.Path(), p.Name())
}

func (r *reader) outPath() string {
	if r.outPkgPath != "" {
		return r.outPkgPath
	}
	return r.pkg.PkgPath
}

func (r *reader) typeExpr(t types.Type) string {
	return types.TypeString(t, r.qualifier)
}

func pathQualifier(p *types.Package) string { return p.Path() }

func pathType(t types.Type) string { return types.TypeString(t, pathQualifier) }

// read reads the tagged struct and, with -for, the type it declares for, and
// builds the file.
func (r *reader) read() (*genFile, error) {
	pkg, req := r.pkg, r.req
	tagNamed, tagStruct, err := lookupStruct(pkg, req.Type)
	if err != nil {
		return nil, err
	}
	valueNamed, valueStruct := tagNamed, tagStruct
	typeName := req.Type
	if req.For != "" {
		valueNamed, valueStruct, err = lookupQualified(pkg, req.For)
		if err != nil {
			return nil, err
		}
		typeName = req.For
	}
	collected, err := r.collectFields(tagNamed, tagStruct, req.Type, true)
	if err != nil {
		return nil, err
	}
	if collected.context == "" {
		return nil, fieldErr(req.Type, "", "no `_ struct{}` field with `stash:\"context=...\"` declares the context")
	}
	if req.For != "" {
		if err := r.matchFor(collected, valueNamed, valueStruct); err != nil {
			return nil, err
		}
	}
	return r.build(collected, typeName, valueNamed, valueStruct, req.For != "", tagNamed)
}

// build makes the file for a collected declaration. foreign says the value
// type is in another package; tagged is the struct that carried the tags,
// which -redact writes print methods on.
func (r *reader) build(collected *collected, typeName string, valueNamed *types.Named, valueStruct *types.Struct, foreign bool, tagged *types.Named) (*genFile, error) {
	pkg, req := r.pkg, r.req
	f := &genFile{pkgName: r.pkgName(), imports: r.imports, typeName: typeName}
	r.file = f
	f.imports.add("context", "context")
	f.imports.add("log/slog", "slog")
	f.imports.add(encryptPath, "encrypt")
	f.imports.add(gensupportPath, "gensupport")

	baseName := valueNamed.Obj().Name()
	f.typeExpr = r.typeExpr(valueNamed)
	f.zeroExpr = f.typeExpr + "{}"
	f.encName = "Encrypted" + baseName
	f.shapeName = lowerFirst(baseName) + "Shape"
	f.shapeSource = f.typeExpr + "{}"
	if req.Name != "" {
		f.encryptFn, f.decryptFn, f.fieldsVar = "Encrypt"+req.Name, "Decrypt"+req.Name, req.Name+"Fields"
		f.declVar, f.codecVar = lowerFirst(req.Name)+"Declaration", lowerFirst(req.Name)+"Codec"
		f.fieldTypePrefix = req.Name
		f.paramName = "values"
	} else {
		f.encryptFn, f.decryptFn, f.fieldsVar = "Encrypt", "Decrypt", "Fields"
		f.declVar, f.codecVar = "declaration", "codec"
		f.paramName = f.pkgName
	}
	if f.paramName == "encrypt" || f.paramName == "eql" || f.paramName == "gensupport" || f.paramName == "context" || f.paramName == "slog" || f.paramName == "ctx" || f.paramName == "cipher" {
		f.paramName = "values"
	}
	if req.Redact {
		if foreign || tagged == nil {
			return nil, fmt.Errorf("stashgen: -redact cannot add print methods to %s, a type in another package", typeName)
		}
		f.redact = true
		f.redactRecv = strings.ToLower(req.Type[:1])
		for _, m := range []string{"String", "LogValue"} {
			if hasMethod(types.NewPointer(tagged), m) {
				return nil, fmt.Errorf("stashgen: -redact: %s already has a %s method", req.Type, m)
			}
		}
	}

	f.decl = Declaration{Type: typeName, Context: collected.context, Opaque: collected.opaque}
	f.unexported = collected.unexported

	// The shape check. A type from another package with an unexported field
	// cannot convert, so the file reads each field by name instead, and the
	// functions take a pointer.
	var conversionNotice string
	switch {
	case !foreign:
		f.shapeFields = shapeOf(valueStruct, r.typeExpr)
	case hasUnexported(valueStruct):
		f.shapeName = ""
		f.isPointer = true
		f.typeExpr = "*" + f.typeExpr
		f.zeroExpr = "nil"
		conversionNotice = fmt.Sprintf("%s has unexported fields, so Go cannot convert it to a copy of its fields. This file reads each field by name: the compiler finds a removed or retyped field, and CI finds an added one.", typeName)
	default:
		f.shapeFields = shapeOf(valueStruct, r.typeExpr)
	}

	if err := r.buildFields(collected); err != nil {
		return nil, err
	}
	if len(f.fields) == 0 && len(f.opaque) == 0 {
		return nil, fieldErr(typeName, "", "stores no field: every field is omitted")
	}

	// Printing.
	sealedCount := 0
	for _, g := range f.fields {
		if g.Sealed() {
			sealedCount++
		}
	}
	if f.decl.Opaque {
		sealedCount = 1
	}
	if sealedCount > 0 && !f.redact && (!hasMethod(valueNamed, "String") || !hasMethod(valueNamed, "LogValue")) {
		f.printsPlaintext = true
		if foreign {
			f.notices = append(f.notices, fmt.Sprintf("%s prints its sealed fields in the clear, and stashgen cannot add print methods to a type from another package.", typeName))
		} else {
			f.notices = append(f.notices, fmt.Sprintf("%s prints its sealed fields in the clear: it has no String or LogValue method. Write them, or run stashgen with -redact.", typeName))
		}
	}
	if conversionNotice != "" {
		f.notices = append(f.notices, conversionNotice)
	}
	if len(f.unexported) > 0 {
		f.notices = append(f.notices, "Not encrypted and not stored: the unexported "+fieldList(f.unexported)+". Tag "+itOrEach(f.unexported)+" `stash:\"-\"` to confirm that.")
	}

	if pkg != nil {
		if err := r.checkDirectives(); err != nil {
			return nil, err
		}
	}
	for _, m := range req.Models {
		if err := r.readModel(m); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// pkgName is the name of the package the file is written into.
func (r *reader) pkgName() string {
	if r.outPkgName != "" {
		return r.outPkgName
	}
	return r.pkg.Name
}

// collectedField is one field of the tagged struct after its tag is read.
type collectedField struct {
	tag      tag
	goName   string
	typ      types.Type
	tags     string // the struct tag without the stash key
	via      string // the embedded struct it is promoted from
	viaType  types.Type
	exported bool
}

type collected struct {
	context    string
	opaque     bool
	fields     []collectedField
	unexported []string
}

// collectFields reads the tags of a struct. An embedded struct of the same
// package adds its tagged fields; an embedded struct with a tag of its own
// promotes every field under that tag.
func (r *reader) collectFields(named *types.Named, st *types.Struct, typeName string, top bool) (*collected, error) {
	c := &collected{}
	// The context first, so the loop knows whether the struct is opaque
	// wherever the `_` field sits.
	for i := range st.NumFields() {
		fld := st.Field(i)
		t, err := parseTag(st.Tag(i))
		if fld.Name() != "_" {
			if err == nil && t.Context != "" {
				return nil, fieldErr(typeName, fld.Name(), "context= goes on a `_ struct{}` field")
			}
			continue
		}
		if err != nil || t.Context == "" {
			return nil, fieldErr(typeName, "_", "a `_` field carries the context tag, `stash:\"context=...\"`")
		}
		if !top {
			return nil, fieldErr(typeName, "_", "an embedded struct declares no context; the outer struct's context applies")
		}
		if c.context != "" {
			return nil, fieldErr(typeName, "_", "the context is declared twice")
		}
		c.context, c.opaque = t.Context, t.Opaque
	}
	for i := range st.NumFields() {
		fld := st.Field(i)
		if fld.Name() == "_" {
			continue
		}
		raw := st.Tag(i)
		t, err := parseTag(raw)
		if err != nil && err != errNoTag {
			return nil, fieldErr(typeName, fld.Name(), "%v", err)
		}
		hasTag := err == nil
		if hasInvalidType(fld.Type()) {
			return nil, fieldErr(typeName, fld.Name(), "its type did not resolve: %s", packageErrors(r.pkg))
		}
		switch {
		case c.opaque:
			// An opaque struct seals as one value: its fields carry no tags
			// but `-`, and every exported field is part of the value.
			switch {
			case hasTag && t.Omit:
				c.fields = append(c.fields, collectedField{tag: t, goName: fld.Name(), typ: fld.Type(), exported: fld.Exported()})
			case hasTag:
				return nil, fieldErr(typeName, fld.Name(), "an opaque struct seals as one value, so its fields carry no tags")
			case !fld.Exported():
				c.unexported = append(c.unexported, fld.Name())
			default:
				c.fields = append(c.fields, collectedField{tag: tag{Name: snakeCase(fld.Name()), Verb: VerbEncrypt}, goName: fld.Name(), typ: fld.Type(), exported: true})
			}
		case fld.Embedded():
			embNamed, embStruct, ok := embeddedStruct(fld.Type())
			if !ok {
				return nil, fieldErr(typeName, fld.Name(), "an embedded field must be a struct, not a pointer or an interface")
			}
			switch {
			case hasTag && t.Omit:
				c.fields = append(c.fields, collectedField{tag: t, goName: fld.Name(), typ: fld.Type(), exported: fld.Exported()})
			case hasTag && t.Verb == VerbPassthrough && t.Name == "":
				for _, pf := range promotedFields(embStruct) {
					c.fields = append(c.fields, collectedField{
						tag:      tag{Name: snakeCase(pf.Name()), Verb: VerbPassthrough},
						goName:   pf.Name(),
						typ:      pf.Type(),
						via:      fld.Name(),
						viaType:  fld.Type(),
						exported: true,
					})
				}
			case hasTag:
				return nil, fieldErr(typeName, fld.Name(), "an embedded struct takes `stash:\",passthrough\"` or `stash:\"-\"`, not %q", strings.TrimPrefix(raw, "stash:"))
			case embNamed != nil && embNamed.Obj().Pkg() != nil && embNamed.Obj().Pkg().Path() == r.pkg.PkgPath:
				inner, err := r.collectFields(embNamed, embStruct, embNamed.Obj().Name(), false)
				if err != nil {
					return nil, err
				}
				c.fields = append(c.fields, inner.fields...)
				c.unexported = append(c.unexported, inner.unexported...)
			default:
				return nil, fieldErr(typeName, fld.Name(), "an embedded struct from another package cannot carry tags; tag the field `stash:\",passthrough\"` to store %s, or `stash:\"-\"` to leave them out", fieldNames(embStruct))
			}
		case !hasTag && !fld.Exported():
			c.unexported = append(c.unexported, fld.Name())
		case !hasTag:
			return nil, fieldErr(typeName, fld.Name(), "no stash tag; every exported field says what happens to it")
		default:
			c.fields = append(c.fields, collectedField{tag: t, goName: fld.Name(), typ: fld.Type(), tags: stripTagKey(raw, tagKey), exported: fld.Exported()})
		}
	}
	return c, nil
}

func embeddedStruct(t types.Type) (*types.Named, *types.Struct, bool) {
	named, _ := t.(*types.Named)
	st, ok := t.Underlying().(*types.Struct)
	return named, st, ok
}

// promotedFields lists the exported fields of a struct and of the structs it
// embeds, as Go promotes them.
func promotedFields(st *types.Struct) []*types.Var {
	var out []*types.Var
	for i := range st.NumFields() {
		f := st.Field(i)
		if f.Embedded() {
			if _, inner, ok := embeddedStruct(f.Type()); ok {
				out = append(out, promotedFields(inner)...)
				continue
			}
		}
		if f.Exported() {
			out = append(out, f)
		}
	}
	return out
}

func fieldNames(st *types.Struct) string {
	var names []string
	for _, f := range promotedFields(st) {
		names = append(names, f.Name())
	}
	return strings.Join(names, ", ")
}

func hasUnexported(st *types.Struct) bool {
	for i := range st.NumFields() {
		if !st.Field(i).Exported() {
			return true
		}
	}
	return false
}

func hasMethod(t types.Type, name string) bool {
	ms := types.NewMethodSet(t)
	for i := range ms.Len() {
		if ms.At(i).Obj().Name() == name {
			return true
		}
	}
	return false
}

func shapeOf(st *types.Struct, typeExpr func(types.Type) string) []shapeField {
	out := make([]shapeField, 0, st.NumFields())
	for i := range st.NumFields() {
		f := st.Field(i)
		out = append(out, shapeField{embedded: f.Embedded(), name: f.Name(), typeExpr: typeExpr(f.Type())})
	}
	return out
}

// matchFor checks the tagged struct against the type it declares for: each
// field names a field of the same name and type, and every exported field of
// the type is named.
func (r *reader) matchFor(c *collected, valueNamed *types.Named, valueStruct *types.Struct) error {
	byName := map[string]*types.Var{}
	for i := range valueStruct.NumFields() {
		byName[valueStruct.Field(i).Name()] = valueStruct.Field(i)
	}
	named := map[string]bool{}
	for _, cf := range c.fields {
		if cf.via != "" {
			return fieldErr(r.req.Type, cf.via, "a struct that declares for %s embeds nothing; name each field", r.req.For)
		}
		vf, ok := byName[cf.goName]
		if !ok {
			return fieldErr(r.req.Type, cf.goName, "%s has no field %s", r.req.For, cf.goName)
		}
		if !types.Identical(vf.Type(), cf.typ) {
			return fieldErr(r.req.Type, cf.goName, "has type %s, and %s.%s has type %s", r.typeExpr(cf.typ), r.req.For, cf.goName, r.typeExpr(vf.Type()))
		}
		named[cf.goName] = true
	}
	var missing []string
	for i := range valueStruct.NumFields() {
		vf := valueStruct.Field(i)
		if vf.Exported() && !named[vf.Name()] {
			missing = append(missing, vf.Name())
		}
	}
	if len(missing) > 0 {
		return fieldErr(r.req.For, missing[0], "not named by %s; every exported field of %s needs a tag there (missing: %s)", r.req.Type, r.req.For, strings.Join(missing, ", "))
	}
	return nil
}

// buildFields turns the collected fields into the declaration, the members
// of the encrypted type and the emitter's fields.
func (r *reader) buildFields(c *collected) error {
	f := r.file
	typeName := r.req.Type
	seen := map[string]string{}
	embedded := map[string]bool{}

	if c.opaque {
		for _, cf := range c.fields {
			if cf.tag.Omit {
				f.decl.Fields = append(f.decl.Fields, Field{Name: snakeCase(cf.goName), GoName: cf.goName, GoType: r.goType(cf.typ), Verb: VerbOmit})
				continue
			}
			g := genField{Field: Field{Name: cf.tag.Name, GoName: cf.goName, GoType: r.goType(cf.typ), Verb: VerbEncrypt}, typeExpr: r.typeExpr(cf.typ)}
			if prev, dup := seen[g.Name]; dup {
				return fieldErr(typeName, cf.goName, "two fields write the name %q: %s and %s", g.Name, prev, cf.goName)
			}
			seen[g.Name] = cf.goName
			f.opaque = append(f.opaque, g)
			f.decl.Fields = append(f.decl.Fields, g.Field)
		}
		f.members = []encMember{{name: "Sealed", typeExpr: "encrypt.Ciphertext"}}
		return nil
	}

	for _, cf := range c.fields {
		t := cf.tag
		name := t.Name
		if t.Omit {
			name = snakeCase(cf.goName)
		}
		if prev, dup := seen[name]; dup {
			return fieldErr(typeName, cf.goName, "two fields write the name %q: %s and %s", name, prev, cf.goName)
		}
		seen[name] = cf.goName
		field := Field{Name: name, GoName: cf.goName, GoType: r.goType(cf.typ), Verb: t.Verb, Indexes: t.Indexes, EQLType: t.EQLType, Identity: t.Identity}
		if t.Omit {
			field.Verb = VerbOmit
		}
		f.decl.Fields = append(f.decl.Fields, field)
		if t.Omit {
			continue
		}
		g := genField{Field: field, typeExpr: r.typeExpr(cf.typ), via: cf.via, tags: cf.tags, pathType: pathType(cf.typ)}
		switch field.Verb {
		case VerbPassthrough:
			g.outputType = g.typeExpr
			g.outputs = []output{{name: "Value", typeExpr: g.typeExpr, pathType: g.pathType}}
		case VerbEncryptInto:
			var eqlType *EQLType
			for i := range r.eql {
				if r.eql[i].Name == field.EQLType {
					eqlType = &r.eql[i]
				}
			}
			if eqlType == nil {
				return fieldErr(typeName, cf.goName, "the engine cannot produce the EQL type %s", field.EQLType)
			}
			f.imports.add(eqlPath, "eql")
			g.outputType = "eql." + eqlType.Name
			g.outputs = []output{{name: "EQL", typeExpr: g.outputType, pathType: eqlPath + "." + eqlType.Name}}
			if eqlType.Query != "" {
				g.queryType = "eql." + eqlType.Query
			}
		default:
			g.outputType = f.encName + cf.goName
			if g.HasCiphertext() {
				g.outputs = append(g.outputs, output{name: "Ciphertext", typeExpr: "encrypt.Ciphertext", pathType: encryptPath + ".Ciphertext"})
			}
			for _, idx := range field.Indexes {
				g.outputs = append(g.outputs, output{name: idx.Name.GoName(), typeExpr: "encrypt." + idx.Name.GoName() + "Term", pathType: encryptPath + "." + idx.Name.GoName() + "Term", index: idx.Name})
			}
		}
		if g.Sealed() {
			g.fieldType = f.fieldTypePrefix + cf.goName + "Field"
		}
		f.fields = append(f.fields, g)
		if cf.via != "" {
			if !embedded[cf.via] {
				embedded[cf.via] = true
				f.members = append(f.members, encMember{embedded: true, name: cf.via, typeExpr: r.typeExpr(cf.viaType), tags: r.embeddedTags(cf.via)})
			}
			continue
		}
		f.members = append(f.members, encMember{name: cf.goName, typeExpr: g.outputType, tags: cf.tags})
	}
	return nil
}

func (r *reader) embeddedTags(fieldName string) string {
	_, st, err := lookupStruct(r.pkg, r.req.Type)
	if err != nil {
		return ""
	}
	for i := range st.NumFields() {
		if st.Field(i).Name() == fieldName {
			return stripTagKey(st.Tag(i), tagKey)
		}
	}
	return ""
}

// goType classifies a Go type for the engine.
func (r *reader) goType(t types.Type) GoType {
	return classify(t, r.typeExpr, map[types.Type]bool{})
}

func classify(t types.Type, typeExpr func(types.Type) string, seen map[types.Type]bool) GoType {
	g := GoType{Name: typeExpr(t), Kind: KindOther}
	if seen[t] {
		return g
	}
	seen[t] = true
	defer delete(seen, t)
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsString != 0:
			g.Kind = KindString
		case u.Info()&types.IsBoolean != 0:
			g.Kind = KindBool
		case u.Info()&types.IsUnsigned != 0:
			g.Kind = KindUint
		case u.Info()&types.IsInteger != 0:
			g.Kind = KindInt
		case u.Info()&types.IsFloat != 0:
			g.Kind = KindFloat
		}
	case *types.Slice:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Byte {
			g.Kind = KindBytes
		} else {
			elem := classify(u.Elem(), typeExpr, seen)
			g.Kind, g.Elem = KindSlice, &elem
		}
	case *types.Array:
		elem := classify(u.Elem(), typeExpr, seen)
		g.Kind, g.Elem = KindSlice, &elem
	case *types.Map:
		elem := classify(u.Elem(), typeExpr, seen)
		g.Kind, g.Elem = KindMap, &elem
	case *types.Pointer:
		elem := classify(u.Elem(), typeExpr, seen)
		g.Kind, g.Elem = KindPointer, &elem
	case *types.Struct:
		if hasUnexported(u) {
			return g
		}
		g.Kind = KindStruct
		for i := range u.NumFields() {
			g.Fields = append(g.Fields, classify(u.Field(i).Type(), typeExpr, seen))
		}
	}
	return g
}

// checkDirectives stops when another go:generate line in the package would
// write the same Encrypt function.
func (r *reader) checkDirectives() error {
	for _, file := range r.pkg.Syntax {
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if !strings.HasPrefix(c.Text, "//go:generate") || !strings.Contains(c.Text, "stashgen") {
					continue
				}
				typ, name := directiveFlags(c.Text)
				if typ == "" || typ == r.req.Type {
					continue
				}
				if "Encrypt"+name == r.file.encryptFn {
					return fmt.Errorf("stashgen: %s and %s would both write %s in package %s; give one of them -name", r.req.Type, typ, r.file.encryptFn, r.pkg.Name)
				}
			}
		}
	}
	return nil
}

// directiveFlags reads -type and -name from a go:generate line.
func directiveFlags(line string) (typ, name string) {
	args := strings.Fields(line)
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				return a[eq+1:]
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "-type" || strings.HasPrefix(a, "-type="), a == "--type" || strings.HasPrefix(a, "--type="):
			typ = next()
		case a == "-name" || strings.HasPrefix(a, "-name="), a == "--name" || strings.HasPrefix(a, "--name="):
			name = next()
		}
	}
	return typ, name
}

// stripTagKey removes one key from a struct tag and keeps the others as
// written, for copying other libraries' tags to the generated type.
func stripTagKey(structTag, key string) string {
	var kept []string
	rest := structTag
	for rest != "" {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			break
		}
		colon := strings.IndexByte(rest, ':')
		if colon <= 0 || colon+1 >= len(rest) || rest[colon+1] != '"' {
			break
		}
		name := rest[:colon]
		end := colon + 2
		for end < len(rest) && rest[end] != '"' {
			if rest[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(rest) {
			break
		}
		pair := rest[:end+1]
		rest = rest[end+1:]
		if name != key {
			kept = append(kept, pair)
		}
	}
	return strings.Join(kept, " ")
}

func fieldList(fields []string) string {
	quoted := make([]string, len(fields))
	for i, f := range fields {
		quoted[i] = fmt.Sprintf("%q", f)
	}
	if len(quoted) == 1 {
		return "field " + quoted[0]
	}
	return "fields " + strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
}

func itOrEach(fields []string) string {
	if len(fields) == 1 {
		return "it"
	}
	return "each"
}
