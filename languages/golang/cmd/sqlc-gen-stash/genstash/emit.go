package genstash

import (
	"bytes"
	"cmp"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/sqlc-dev/plugin-sdk-go/plugin"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/gengo"
)

const (
	// companionFile is the file the plugin adds to sqlc-gen-go's output.
	companionFile = "stash.go"
	// generatedVersion is the gensupport version constant the generated
	// code is written against.
	generatedVersion = "gensupport.GeneratedVersion2"
)

// column is the encrypted column field f holds, or nil.
func (g *generator) column(f gengo.Field) *encryptedColumn {
	return g.byKey[g.columnKey(f)]
}

// columnKey is the table.column field f holds, or "" when sqlc can't trace
// it to a table.
func (g *generator) columnKey(f gengo.Field) string {
	if f.Column.GetTable().GetName() == "" {
		return ""
	}
	// A query's column has its name in the table in OriginalName when the
	// query gives it an alias.
	return g.qualified(f.Column.GetTable()) + "." + cmp.Or(f.Column.GetOriginalName(), f.Column.GetName())
}

// qualified names a table as sqlc's column overrides do: by its name in the
// default schema, and as schema.name outside it.
func (g *generator) qualified(t *plugin.Identifier) string {
	if t.GetSchema() == "" || t.GetSchema() == g.defaultSchema {
		return t.GetName()
	}

	return t.GetSchema() + "." + t.GetName()
}

// encrypted says some field of s holds an encrypted column.
func (g *generator) encrypted(s *gengo.Struct) bool {
	return slices.ContainsFunc(s.Fields, func(f gengo.Field) bool { return g.column(f) != nil })
}

// nullable says field f's value can be NULL, so a field of an EQL type is a
// pointer to its encrypt/eql type.
func nullable(f gengo.Field) bool {
	return !f.Column.GetNotNull() && !f.Column.GetIsArray()
}

// group is the encrypted fields of one struct that come from one occurrence
// of one table. Each group is opened with one codec, so a row that joins
// tables, or one table twice, makes one SDK call per group.
type group struct {
	codec  *codec
	fields []gengo.Field
}

// codec is one generated gensupport codec: a declaration over some encrypted
// columns of one table, with plaintext and sealed adapter structs.
type codec struct {
	name    string
	table   string
	columns []codecColumn
}

type codecColumn struct {
	column   *encryptedColumn
	nullable bool
}

func (c codecColumn) key() string {
	return fmt.Sprintf("%s:%t", c.column.Name, c.nullable)
}

// emit reads the structs sqlc-gen-go's package declares and writes the
// companion file: plaintext structs, public conversion helpers, opt-in
// query methods, and, with stash.EmitTableFields, a value for every
// column of every table that isn't a view. The file is in its own package,
// named after sqlc-gen-go's with stash appended, in a folder of that name
// under out. sqlcImport is the import path of sqlc-gen-go's package.
func emit(
	pkg *gengo.Package,
	catalog *plugin.Catalog,
	views map[string]bool,
	columns []encryptedColumn,
	stash StashOptions,
	sqlcImport string,
) ([]*plugin.File, error) {
	g := &generator{
		opts:          pkg.Options,
		fset:          token.NewFileSet(),
		pkg:           pkg.Options.Package + "stash",
		sqlcPkg:       pkg.Options.Package,
		sqlcImport:    sqlcImport,
		imports:       map[string]string{},
		codecs:        map[string]*codec{},
		names:         map[string]bool{},
		defaultSchema: catalog.GetDefaultSchema(),
		byKey:         map[string]*encryptedColumn{},
	}
	for p, name := range pkg.Imports {
		g.imports[p] = cmp.Or(name, importName(p))
	}
	for i, c := range columns {
		g.byKey[c.Key] = &columns[i]
	}
	structs := pkg.Declared()
	byName := map[string]*gengo.Struct{}
	for _, s := range structs {
		byName[s.Name] = s.Struct
	}
	for _, s := range structs {
		if !g.encrypted(s.Struct) {
			continue
		}
		var err error
		if s.Params {
			err = g.paramsCompanion(s)
		} else if err = g.checkEmbeds(s.Struct, byName); err == nil {
			err = g.companion(s, gengo.ModelsFile(pkg.Options), columns)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := g.queryMethods(pkg, queryMethodsOptions{
		EncryptParams:  stash.EmitMethodsWithParamEncryption,
		DecryptResults: stash.EmitMethodsWithResultDecryption,
	}, byName); err != nil {
		return nil, err
	}
	var runtime bool
	if stash.EmitTableFields {
		var err error
		if runtime, err = g.fields(pkg, views); err != nil {
			return nil, err
		}
	}
	if g.body.Len() == 0 {
		return nil, nil
	}
	src, err := g.file()
	if err != nil {
		return nil, err
	}
	files := []*plugin.File{{Name: path.Join(g.pkg, companionFile), Contents: src}}
	if runtime {
		files = append(files, &plugin.File{Name: path.Join(g.pkg, fieldTypesFile), Contents: g.runtimeFile()})
	}

	return files, nil
}

// checkEmbeds refuses a struct with encrypted fields that also holds, through
// sqlc.embed, a struct with encrypted fields: Plain<Struct> would carry the
// embedded struct's ciphertext through as it is, beside fields in plaintext.
func (g *generator) checkEmbeds(s *gengo.Struct, structs map[string]*gengo.Struct) error {
	for _, f := range s.Fields {
		inner := structs[strings.TrimLeft(f.Type, "*")]
		if g.column(f) == nil && inner != nil && g.encrypted(inner) {
			return &Error{Field: s.Name + "." + f.Name, Err: fmt.Errorf("%w: %s; list the embedded table's columns instead of using sqlc.embed", ErrEncryptedEmbed, inner.Name)}
		}
	}

	return nil
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, e)

	return b.String()
}

// importName is the name a package is used by when its import has none:
// the last path element, skipping a major version suffix.
func importName(p string) string {
	base := path.Base(p)
	if len(base) > 1 && base[0] == 'v' && strings.Trim(base[1:], "0123456789") == "" {
		base = path.Base(path.Dir(p))
	}

	return base
}

type generator struct {
	opts *gengo.Options
	fset *token.FileSet
	// pkg is the generated file's package, and sqlcPkg and sqlcImport
	// sqlc-gen-go's.
	pkg        string
	sqlcPkg    string
	sqlcImport string
	imports    map[string]string
	codecs     map[string]*codec
	codecOrd   []*codec
	body       bytes.Buffer
	// names are the top-level names the file declares.
	names map[string]bool
	// defaultSchema is the catalog's default schema, and byKey the
	// encrypted columns by their Key.
	defaultSchema string
	byKey         map[string]*encryptedColumn
}

func (g *generator) printf(tmpl string, args ...any) {
	fmt.Fprintf(&g.body, tmpl, args...)
}

// declare claims top-level names the file declares for what, refusing a
// name it declares twice.
func (g *generator) declare(what string, names ...string) error {
	for _, name := range names {
		if g.names[name] {
			return fmt.Errorf("%s is generated twice, the second time for %s", name, what)
		}
		g.names[name] = true
	}

	return nil
}

// ref names a type declared in sqlc-gen-go's package.
func (g *generator) ref(name string) string {
	return g.sqlcPkg + "." + name
}

// fieldType is the type of a field sqlc-gen-go writes, as the generated file
// writes it: every type name that isn't predeclared is qualified with
// sqlc-gen-go's package. That covers the types sqlc-gen-go
// declares and the ones an override names in that package without an
// import, which are in files sqlc-gen-go doesn't write.
func (g *generator) fieldType(structName string, f gengo.Field) (string, error) {
	var qualify func(ast.Expr) (ast.Expr, error)
	qualify = func(e ast.Expr) (ast.Expr, error) {
		switch t := e.(type) {
		case *ast.Ident:
			if _, ok := types.Universe.Lookup(t.Name).(*types.TypeName); ok {
				return t, nil
			}

			return &ast.SelectorExpr{X: ast.NewIdent(g.sqlcPkg), Sel: ast.NewIdent(t.Name)}, nil
		case *ast.SelectorExpr:
			return t, nil
		case *ast.StarExpr:
			x, err := qualify(t.X)

			return &ast.StarExpr{X: x}, err
		case *ast.ArrayType:
			elt, err := qualify(t.Elt)

			return &ast.ArrayType{Len: t.Len, Elt: elt}, err
		case *ast.MapType:
			key, err := qualify(t.Key)
			if err != nil {
				return nil, err
			}
			value, err := qualify(t.Value)

			return &ast.MapType{Key: key, Value: value}, err
		case *ast.InterfaceType:
			if len(t.Methods.List) == 0 {
				return t, nil
			}
		}

		return nil, fmt.Errorf("%s.%s has the type %s, which sqlc-gen-stash can't name from its own package", structName, f.Name, f.Type)
	}
	expr, err := parser.ParseExpr(f.Type)
	if err != nil {
		return "", fmt.Errorf("sqlc-gen-go's %s.%s: %w", structName, f.Name, err)
	}
	e, err := qualify(expr)
	if err != nil {
		return "", err
	}

	return exprString(g.fset, e), nil
}

// companion writes the plaintext struct for a row s and its Decrypt
// function, and an Encrypt function for a table model.
func (g *generator) companion(s gengo.Declared, modelsFile string, columns []encryptedColumn) error {
	plain, decrypt, encrypt, row := "Plain"+s.Name, "Decrypt"+s.Name, "Encrypt"+s.Name, g.ref(s.Name)
	groups, err := g.plainCompanion(s.Struct, decrypt, encrypt)
	if err != nil {
		return err
	}
	ptr := ""
	if g.opts.EmitResultStructPointers {
		ptr = "*"
	}
	g.printf("// %s opens the encrypted fields of each row, with one SDK call for each\n// table the row reads. The result has one element for each row, in order.\n", decrypt)
	g.printf("func %s(\nctx context.Context,\nd encrypt.Decrypter,\nrows []%s%s,\n) ([]%s%s, error) {\n", decrypt, ptr, row, ptr, plain)
	g.convert(decrypt, s.Struct, groups, ptr, plain, "Sealed", "Decrypt(ctx, d, in)")
	g.printf("}\n\n")

	// sqlc-gen-go can put a struct in the models file that isn't a whole
	// table model; that is treated as a query row.
	if s.File == modelsFile && fullTable(groups, columns) {
		g.printf("// %s seals the encrypted fields of each row, with one SDK call. The result\n// has one element for each row, in order.\n", encrypt)
		g.printf("func %s(\nctx context.Context,\nc *encrypt.Cipher,\nrows []%s%s,\n) ([]%s%s, error) {\n", encrypt, ptr, plain, ptr, row)
		g.convert(encrypt, s.Struct, groups, ptr, row, "Plain", "Encrypt(ctx, c, in)")
		g.printf("}\n\n")
	}

	return nil
}

// paramsCompanion writes the plaintext struct for a query's parameters s
// and its Encrypt function, which takes what the query's method takes: one
// value, or a slice for a :batch* or :copyfrom query. Parameters are
// written, never read back, so they get no Decrypt.
func (g *generator) paramsCompanion(s gengo.Declared) error {
	plain, encrypt, params := "Plain"+s.Name, "Encrypt"+s.Name, g.ref(s.Name)
	groups, err := g.plainCompanion(s.Struct, encrypt)
	if err != nil {
		return err
	}
	ptr := ""
	if g.opts.EmitParamsStructPointers {
		ptr = "*"
	}
	if s.Batch {
		g.printf("// %s seals the encrypted fields of each value, with one SDK call for each\n// table the parameters write or compare with. The result has one element for\n// each value, in order.\n", encrypt)
		g.printf("func %s(\nctx context.Context,\nc *encrypt.Cipher,\nrows []%s%s,\n) ([]%s%s, error) {\n", encrypt, ptr, plain, ptr, params)
		g.copyRows(encrypt, s.Struct, ptr, params)
		g.convertGroups(encrypt, groups, "Plain", "Encrypt(ctx, c, in)")
		g.printf("}\n\n")

		return nil
	}
	g.printf("// %s seals the encrypted fields of p, with one SDK call for each table the\n// parameters write or compare with.\n", encrypt)
	g.printf("func %s(\nctx context.Context,\nc *encrypt.Cipher,\np %s%s,\n) (%s%s, error) {\n", encrypt, ptr, plain, ptr, params)
	g.encryptOne(encrypt, s.Struct, groups, ptr, params)
	g.printf("}\n\n")

	return nil
}

// encryptOne writes the body of an Encrypt function for one value of a
// query's parameters s. to is the result's struct.
func (g *generator) encryptOne(fn string, s *gengo.Struct, groups []group, ptr, to string) {
	zero := to + "{}"
	if ptr != "" {
		zero = "nil"
		g.printf("\tif p == nil {\n\t\treturn nil, fmt.Errorf(\"%s: the parameters are nil\")\n\t}\n", fn)
	}
	g.printf("\tout := %s%s{\n", strings.Replace(ptr, "*", "&", 1), to)
	for _, f := range s.Fields {
		if g.column(f) == nil {
			g.printf("\t\t%s: p.%s,\n", f.Name, f.Name)
		}
	}
	g.printf("\t}\n")
	for _, gr := range groups {
		g.printf("\t{\n\t\tconverted, err := %sCodec.Encrypt(ctx, c, []%sPlain{{", gr.codec.name, gr.codec.name)
		for i, f := range gr.fields {
			if i > 0 {
				g.printf(", ")
			}
			g.printf("F%d: p.%s", i, f.Name)
		}
		g.printf("}})\n")
		g.printf("\t\tif err != nil {\n\t\t\treturn %s, fmt.Errorf(\"%s: %%w\", err)\n\t\t}\n", zero, fn)
		for i, f := range gr.fields {
			g.printf("\t\tout.%s = converted[0].F%d\n", f.Name, i)
		}
		g.printf("\t}\n")
	}
	g.printf("\treturn out, nil\n")
}

// plainCompanion claims the names generated for s, with more, writes its
// plaintext struct, and returns its encrypted fields in codec groups.
func (g *generator) plainCompanion(s *gengo.Struct, more ...string) ([]group, error) {
	plain := "Plain" + s.Name
	if err := g.declare(s.Name, append([]string{plain}, more...)...); err != nil {
		return nil, err
	}

	for _, f := range s.Fields {
		if g.column(f) != nil && f.Column.GetIsSqlcSlice() {
			return nil, &Error{Field: s.Name + "." + f.Name, Err: fmt.Errorf("%w: sqlc.slice parameters cannot be encrypted by conversion helpers", ErrEQLArray)}
		}
		// A query value (a parameter cast to a query domain) is no column's:
		// the caller derives it with a field entry's query method.
		if g.column(f) == nil && strings.HasPrefix(strings.TrimPrefix(f.Type, "*"), "eql.") && !strings.HasSuffix(f.Type, "Query") {
			// sqlc couldn't name the column's table, for example because the
			// query reads it through a CTE, so its plaintext field would
			// hold ciphertext.
			return nil, &Error{Field: s.Name + "." + f.Name, Err: fmt.Errorf("%w; select it straight from its table", ErrUntraceableField)}
		}
	}

	var hidden []string
	g.printf("// %s is %s with its encrypted fields in plaintext.\n", plain, g.ref(s.Name))
	g.printf("type %s struct {\n", plain)
	for _, f := range s.Fields {
		typ, err := g.fieldType(s.Name, f)
		if err != nil {
			return nil, err
		}
		if c := g.column(f); c != nil {
			typ = plaintextType(c)
			if nullable(f) {
				typ = "*" + typ
			}
			hidden = append(hidden, strconv.Quote(f.Name))
		}
		g.printf("\t%s %s\n", f.Name, typ)
	}
	g.printf("}\n\n")
	g.printf("// String hides the plaintext of the encrypted fields.\n")
	g.printf("func (p %s) String() string {\n\treturn gensupport.Redacted(%q, nil, %s)\n}\n\n", plain, plain, strings.Join(hidden, ", "))
	g.printf("// GoString hides the plaintext of the encrypted fields from %%#v.\n")
	g.printf("func (p %s) GoString() string {\n\treturn p.String()\n}\n\n", plain)
	g.printf("// LogValue hides the plaintext of the encrypted fields.\n")
	g.printf("func (p %s) LogValue() slog.Value {\n\treturn gensupport.RedactedLog(nil, %s)\n}\n\n", plain, strings.Join(hidden, ", "))

	return g.groups(s), nil
}

// convert writes the body of a Decrypt function (from sqlc's rows to the
// plaintext companions) or an Encrypt function (the other way). to is the
// result's struct, from the codec adapter the rows become, and call the
// codec call that converts them.
func (g *generator) convert(fn string, s *gengo.Struct, groups []group, ptr, to, from, call string) {
	g.copyRows(fn, s, ptr, to)
	g.convertGroups(fn, groups, from, call)
}

// copyRows writes the first half of convert: out, with one element of to for
// each row and its fields that aren't encrypted copied.
func (g *generator) copyRows(fn string, s *gengo.Struct, ptr, to string) {
	g.printf("\tif len(rows) == 0 {\n\t\treturn nil, nil\n\t}\n")
	if ptr != "" {
		g.printf("\tfor i, r := range rows {\n\t\tif r == nil {\n\t\t\treturn nil, fmt.Errorf(\"%s: row %%d is nil\", i)\n\t\t}\n\t}\n", fn)
	}
	g.printf("\tout := make([]%s%s, len(rows))\n", ptr, to)
	loop := "i, r"
	if !slices.ContainsFunc(s.Fields, func(f gengo.Field) bool { return g.column(f) == nil }) {
		// Every field is encrypted, so the codecs fill them all.
		loop = "i"
	}
	g.printf("\tfor %s := range rows {\n\t\tout[i] = %s%s{\n", loop, strings.Replace(ptr, "*", "&", 1), to)
	for _, f := range s.Fields {
		if g.column(f) == nil {
			g.printf("\t\t\t%s: r.%s,\n", f.Name, f.Name)
		}
	}
	g.printf("\t\t}\n\t}\n")
}

// convertGroups writes the second half of convert: one codec call for each
// group, which fills the group's fields of out, and the return.
func (g *generator) convertGroups(fn string, groups []group, from, call string) {
	for _, gr := range groups {
		g.printf("\t{\n\t\tin := make([]%s%s, len(rows))\n", gr.codec.name, from)
		g.printf("\t\tfor i, r := range rows {\n\t\t\tin[i] = %s%s{", gr.codec.name, from)
		for i, f := range gr.fields {
			if i > 0 {
				g.printf(", ")
			}
			g.printf("F%d: r.%s", i, f.Name)
		}
		g.printf("}\n\t\t}\n")
		g.printf("\t\tconverted, err := %sCodec.%s\n", gr.codec.name, call)
		g.printf("\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t\t}\n", fn)
		g.printf("\t\tfor i, v := range converted {\n")
		for i, f := range gr.fields {
			g.printf("\t\t\tout[i].%s = v.F%d\n", f.Name, i)
		}
		g.printf("\t\t}\n\t}\n")
	}
	g.printf("\treturn out, nil\n")
}

// groups splits a struct's encrypted fields into table occurrences: a field
// joins the first group of its table that doesn't have its column yet, so a
// self join or a repeated column makes a second group.
func (g *generator) groups(s *gengo.Struct) []group {
	type building struct {
		table   string
		fields  []gengo.Field
		columns map[string]bool
	}
	var bs []*building
	for _, f := range s.Fields {
		c := g.column(f)
		if c == nil {
			continue
		}
		i := slices.IndexFunc(bs, func(b *building) bool { return b.table == c.Table && !b.columns[c.Name] })
		if i < 0 {
			bs = append(bs, &building{table: c.Table, columns: map[string]bool{}})
			i = len(bs) - 1
		}
		bs[i].fields = append(bs[i].fields, f)
		bs[i].columns[c.Name] = true
	}
	groups := make([]group, len(bs))
	for i, b := range bs {
		groups[i] = group{codec: g.codecFor(b.table, b.fields), fields: b.fields}
	}

	return groups
}

// codecFor returns the codec for these columns of a table, sharing one
// between structs that read the same columns with the same nullability.
func (g *generator) codecFor(table string, fields []gengo.Field) *codec {
	cols := make([]codecColumn, len(fields))
	keys := make([]string, len(fields))
	for i, f := range fields {
		cols[i] = codecColumn{column: g.column(f), nullable: nullable(f)}
		keys[i] = cols[i].key()
	}
	key := table + "|" + strings.Join(keys, ",")
	if c, ok := g.codecs[key]; ok {
		return c
	}
	c := &codec{name: fmt.Sprintf("stash%d", len(g.codecOrd)), table: table, columns: cols}
	g.codecs[key] = c
	g.codecOrd = append(g.codecOrd, c)

	return c
}

// fullTable reports whether the groups are one occurrence of one table with
// every encrypted column of that table.
func fullTable(groups []group, columns []encryptedColumn) bool {
	if len(groups) != 1 {
		return false
	}
	n := 0
	for _, c := range columns {
		if c.Table == groups[0].codec.table {
			n++
		}
	}

	return len(groups[0].fields) == n
}

func plaintextType(c *encryptedColumn) string {
	switch c.Type.Plaintext {
	case "string", "bool", "int16", "int32", "int64", "float32", "float64":
		return c.Type.Plaintext
	case "date":
		return "encrypt.Date"
	case "decimal":
		return "encrypt.Decimal"
	case "timestamp":
		return "time.Time"
	case "json":
		return "json.RawMessage"
	default:
		// encryptedColumns only accepts producible types, which all have a
		// plaintext kind.
		panic("no plaintext type for " + c.Type.Name)
	}
}

var kindNames = map[string]string{
	"string": "String", "bool": "Bool", "int16": "Int16", "int32": "Int32", "int64": "Int64",
	"float32": "Float32", "float64": "Float64", "date": "Date", "decimal": "Decimal",
	"timestamp": "Timestamp", "json": "JSON",
}

// declarationExpr is the gensupport declaration of some encrypted columns of
// a table.
func declarationExpr(table string, columns []codecColumn) string {
	var b strings.Builder
	fmt.Fprintf(&b, "gensupport.Declare(%q)", table)
	for _, col := range columns {
		cc := col.column
		fmt.Fprintf(&b, ".\n\t\tEncryptInto(%q, gensupport.%s, %q)", cc.Name, kindNames[cc.Type.Plaintext], cc.Type.Name)
		if col.nullable {
			fmt.Fprintf(&b, ".\n\t\tNull(%q, gensupport.NullSQL)", cc.Name)
		}
		if cc.Identity != cc.Name {
			fmt.Fprintf(&b, ".\n\t\tIdentity(%q, %q)", cc.Name, cc.Identity)
		}
	}

	return b.String()
}

// writeCodec writes a codec's declaration, adapter structs and gensupport
// codec.
func writeCodec(b *bytes.Buffer, c *codec) {
	p := func(tmpl string, args ...any) { fmt.Fprintf(b, tmpl, args...) }
	p("type %sPlain struct {\n", c.name)
	for i, col := range c.columns {
		typ := plaintextType(col.column)
		if col.nullable {
			typ = "*" + typ
		}
		p("\tF%d %s\n", i, typ)
	}
	p("}\n\n")
	p("type %sSealed struct {\n", c.name)
	for i, col := range c.columns {
		typ := "eql." + col.column.Type.GoName
		if col.nullable {
			typ = "*" + typ
		}
		p("\tF%d %s\n", i, typ)
	}
	p("}\n\n")

	p("var %sCodec = gensupport.New(gensupport.Generated[%sPlain, %sSealed]{\n", c.name, c.name, c.name)
	p("\tTypeName: %q,\n", c.table)
	p("\tDeclaration: %s,\n", declarationExpr(c.table, c.columns))
	// The adapters never leave the generated functions, so nothing prints
	// them.
	p("\tPrintsPlaintext: false,\n")

	p("\tSource: func(v %sPlain) gensupport.Values {\n\t\treturn gensupport.Values{\n", c.name)
	for i, col := range c.columns {
		if col.nullable {
			p("\t\t\t%q: gensupport.Deref(v.F%d),\n", col.column.Name, i)
		} else {
			p("\t\t\t%q: v.F%d,\n", col.column.Name, i)
		}
	}
	p("\t\t}\n\t},\n")

	p("\tSeal: func(rec gensupport.Record) (%sSealed, error) {\n\t\tvar e %sSealed\n", c.name, c.name)
	for i, col := range c.columns {
		typ := "eql." + col.column.Type.GoName
		if col.nullable {
			p("\t\tif o, ok := rec[%q]; ok {\n\t\t\tv := %s(o.EQL)\n\t\t\te.F%d = &v\n\t\t}\n", col.column.Name, typ, i)
		} else {
			p("\t\te.F%d = %s(rec[%q].EQL)\n", i, typ, col.column.Name)
		}
	}
	p("\t\treturn e, nil\n\t},\n")

	p("\tOpen: func(e %sSealed) gensupport.Record {\n\t\trec := gensupport.Record{}\n", c.name)
	for i, col := range c.columns {
		if col.nullable {
			p("\t\tif e.F%d != nil {\n\t\t\trec[%q] = gensupport.Output{EQL: *e.F%d}\n\t\t}\n", i, col.column.Name, i)
		} else {
			p("\t\trec[%q] = gensupport.Output{EQL: e.F%d}\n", col.column.Name, i)
		}
	}
	p("\t\treturn rec\n\t},\n")

	p("\tValue: func(_ %sSealed, vals gensupport.Values) (%sPlain, error) {\n\t\tvar v %sPlain\n\t\tvar err error\n", c.name, c.name, c.name)
	for i, col := range c.columns {
		typ := plaintextType(col.column)
		get := "Get"
		if col.column.Type.Plaintext == "json" {
			get = "GetDocument"
		}
		if col.nullable {
			get += "Ptr"
		}
		p("\t\tif v.F%d, err = gensupport.%s[%s](vals, %q); err != nil {\n\t\t\treturn %sPlain{}, err\n\t\t}\n", i, get, typ, col.column.Name, c.name)
	}
	p("\t\treturn v, nil\n\t},\n")
	p("})\n\n")
}

// file assembles the companion file with the imports it uses.
func (g *generator) file() ([]byte, error) {
	var codecs bytes.Buffer
	for _, c := range g.codecOrd {
		writeCodec(&codecs, c)
	}

	candidates := map[string]string{
		"context":       "context",
		"encoding/json": "json",
		"fmt":           "fmt",
		"log/slog":      "slog",
		"time":          "time",
		"github.com/cipherstash/stack/languages/golang/encrypt":            "encrypt",
		"github.com/cipherstash/stack/languages/golang/encrypt/gensupport": "gensupport",
		eqlImport: "eql",
	}
	for p, name := range g.imports {
		if _, ok := candidates[p]; !ok {
			candidates[p] = name
		}
	}
	for p, name := range candidates {
		if name == g.sqlcPkg {
			return nil, &Error{Option: "options.go.package", Err: fmt.Errorf("%w: %s is the name of %s, which %s also imports", ErrInvalidOption, g.sqlcPkg, p, companionFile)}
		}
	}
	candidates[g.sqlcImport] = g.sqlcPkg

	var src bytes.Buffer
	fmt.Fprintf(&src, "%spackage %s\n\nimport (\n", g.header(), g.pkg)
	used, err := usedPackages(g.pkg, g.body.String()+codecs.String())
	if err != nil {
		return nil, err
	}
	// Standard library imports first, then the rest, as goimports groups them.
	var std, other []string
	for p, name := range candidates {
		if !used[name] {
			continue
		}
		if strings.Contains(strings.Split(p, "/")[0], ".") {
			other = append(other, p)
		} else {
			std = append(std, p)
		}
	}
	slices.Sort(std)
	slices.Sort(other)
	for i, group := range [][]string{std, other} {
		for j, p := range group {
			// A blank line between the two groups.
			sep := ""
			if i > 0 && j == 0 && len(std) > 0 {
				sep = "\n"
			}
			if name := candidates[p]; name != importName(p) {
				fmt.Fprintf(&src, "%s\t%s %q\n", sep, name, p)
			} else {
				fmt.Fprintf(&src, "%s\t%q\n", sep, p)
			}
		}
	}
	fmt.Fprintf(&src, ")\n\n"+
		"// Stops compiling when the SDK does not accept this version of generated code.\n"+
		"const _ = %s\n\n%s%s", generatedVersion, g.body.String(), codecs.String())

	out, err := format.Source(src.Bytes())
	if err != nil {
		return nil, fmt.Errorf("formatting %s: %w\n%s", companionFile, err, src.String())
	}

	return out, nil
}

// header is what each generated file starts with, before its package
// clause.
func (g *generator) header() string {
	h := "// Code generated by sqlc-gen-stash. DO NOT EDIT.\n\n"
	if g.opts.BuildTags != "" {
		h += "//go:build " + g.opts.BuildTags + "\n\n"
	}

	return h
}

// usedPackages lists the package names the code refers to, as the X of a
// selector expression.
func usedPackages(pkg, code string) (map[string]bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), companionFile, "package "+pkg+"\n"+code, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parsing the generated %s: %w", companionFile, err)
	}
	used := map[string]bool{"gensupport": true}
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				used[id.Name] = true
			}
		}

		return true
	})

	return used, nil
}
