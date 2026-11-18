package genstash

import (
	_ "embed"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/cipherstash/stack/languages/golang/stashgen"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/gengo"
)

// readModels lists the model of every table that isn't one of views,
// whatever omit_unused_structs says, and the types omit_unused_structs left
// out of sqlc-gen-go's package.
func (g *generator) readModels(pkg *gengo.Package, views map[string]bool) ([]gengo.Struct, map[string]bool) {
	dropped := map[string]bool{}
	for _, e := range pkg.AllEnums {
		if !slices.ContainsFunc(pkg.Enums, func(k gengo.Enum) bool { return k.Name == e.Name }) {
			dropped[e.Name], dropped["Null"+e.Name] = true, true
		}
	}
	var models []gengo.Struct
	for _, s := range pkg.Tables {
		if !slices.ContainsFunc(pkg.Structs, func(k gengo.Struct) bool { return k.Name == s.Name }) {
			dropped[s.Name] = true
		}
		if !views[g.qualified(s.Table)] && len(s.Fields) > 0 {
			models = append(models, s)
		}
	}

	return models, dropped
}

// fieldTypes is the runtime file: Column and the encrypted field types,
// which the per-column values fields writes are of.
//
//go:embed fieldtypes/fieldtypes.go
var fieldTypes string

// fieldTypesFile is the name the runtime file is written as, beside
// companionFile.
const fieldTypesFile = "fieldtypes.go"

// runtimeFile is the runtime file as the generated package's: with the
// generated header and the package's name.
func (g *generator) runtimeFile() []byte {
	return []byte(g.header() + strings.Replace(fieldTypes, "\npackage fieldtypes\n", "\npackage "+g.pkg+"\n", 1))
}

// fields writes the per-column values of every table's model: a
// <Model>Fields value for each, with a Column[T] for each plaintext column
// and, for each encrypted one, the encrypted field type of the runtime file
// whose methods are the operators the engine answers on it, through an
// alias for its EQL type. It reports whether it wrote any, and so needs the
// runtime file.
func (g *generator) fields(pkg *gengo.Package, views map[string]bool) (bool, error) {
	models, dropped := g.readModels(pkg, views)
	if len(models) == 0 {
		return false, nil
	}
	if err := g.checkDropped(models, dropped); err != nil {
		return false, err
	}
	type alias struct{ eqlType, typ string }
	aliases := map[string]alias{}
	for _, m := range models {
		for _, f := range m.Fields {
			c := g.column(f)
			if c == nil {
				continue
			}
			typ, err := runtimeType(c)
			if err != nil {
				return false, err
			}
			name := c.Type.GoName + "Field"
			if a, ok := aliases[name]; ok && a.typ != typ {
				return false, &Error{Column: c.Key, Err: fmt.Errorf("%w: the engine answers other operators on it than on another column of %s, so they can't share %s", ErrUnsupportedOperator, c.Type.Name, name)}
			}
			aliases[name] = alias{c.Type.Name, typ}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(aliases)) {
		if err := g.declare("encrypted columns", name); err != nil {
			return false, err
		}
		g.printf("// %s is an encrypted column of the EQL type %s.\ntype %s = %s\n\n", name, aliases[name].eqlType, name, aliases[name].typ)
	}
	for _, m := range models {
		if err := g.model(m); err != nil {
			return false, err
		}
	}

	return true, nil
}

// runtimeTypes are the encrypted field types of the runtime file, with the
// operators each has a method for, sorted.
var runtimeTypes = []struct {
	name      string
	operators []string
}{
	{"Stored", nil},
	{"Eq", []string{"eq"}},
	{"Ord", []string{"gt", "gte", "lt", "lte"}},
	{"Match", []string{"matches"}},
	{"EqOrd", []string{"eq", "gt", "gte", "lt", "lte"}},
	{"Search", []string{"eq", "gt", "gte", "lt", "lte", "matches"}},
	{"Document", []string{"child_count", "children", "contained_by", "contains", "eq_at", "match", "selector", "subtree"}},
}

// runtimeType is the encrypted field type of column c: the runtime type
// whose methods are exactly the operators the engine answers on it, with
// c's plaintext, stored and query types. An operator set no runtime type
// has, or an operator whose term no method derives, is refused.
func runtimeType(c *encryptedColumn) (string, error) {
	value := plaintextType(c)
	names := make([]string, len(c.Operators))
	for i, op := range c.Operators {
		switch {
		case c.Type.Query == "":
			return "", &Error{Column: c.Key, Err: fmt.Errorf("%w: the engine answers %s on %s, which has no query type", ErrUnsupportedOperator, op.Name, c.Type.Name)}
		case op.Pair:
			return "", &Error{Column: c.Key, Err: fmt.Errorf("%w: the engine answers %s on %s with two values, and an EQL query value is one", ErrUnsupportedOperator, op.Name, c.Type.Name)}
		case op.Probabilistic && (op.Index != stashgen.IndexMatch || value != "string"):
			return "", &Error{Column: c.Key, Err: fmt.Errorf("%w: the engine answers %s on %s with a probabilistic term through the %s index, and the SDK verifies only a match index over a string", ErrUnsupportedOperator, op.Name, c.Type.Name, op.Index)}
		case op.Probabilistic != (op.Name == "matches"):
			return "", &Error{Column: c.Key, Err: fmt.Errorf("%w: the engine answers %s on %s with a term of another fidelity than its method derives", ErrUnsupportedOperator, op.Name, c.Type.Name)}
		}
		names[i] = op.Name
	}
	slices.Sort(names)
	name := ""
	for _, t := range runtimeTypes {
		if slices.Equal(t.operators, names) {
			name = t.name

			break
		}
	}
	if name == "" {
		return "", &Error{Column: c.Key, Err: fmt.Errorf("%w: the engine answers %s on %s, and no encrypted field type of sqlc-gen-stash has methods for exactly those", ErrUnsupportedOperator, strings.Join(names, ", "), c.Type.Name)}
	}
	stored := "eql." + c.Type.GoName
	query := "eql." + stashgen.EQLGoName(c.Type.Query)
	switch name {
	case "Stored":
		return fmt.Sprintf("Stored[%s, %s]", value, stored), nil
	case "Document":
		entry := "eql." + stashgen.EQLGoName("JsonEntry")
		predicate := strings.TrimSuffix(query, "Query") + "PredicateQuery"

		return fmt.Sprintf("Document[%s, %s, %s, %s, %s]", value, stored, query, entry, predicate), nil
	default:
		return fmt.Sprintf("%s[%s, %s, %s]", name, value, stored, query), nil
	}
}

// checkDropped refuses a plaintext column whose Go type names a type of
// sqlc-gen-go's package that omit_unused_structs left out of the package,
// an enum no query uses: its <Model>Fields would name a type that doesn't
// exist.
func (g *generator) checkDropped(models []gengo.Struct, dropped map[string]bool) error {
	var problems []error
	for _, m := range models {
		for _, f := range m.Fields {
			if g.column(f) != nil {
				continue
			}
			expr, err := parser.ParseExpr(f.Type)
			if err != nil {
				return fmt.Errorf("sqlc-gen-go's %s.%s: %w", m.Name, f.Name, err)
			}
			ast.Inspect(expr, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					return false
				case *ast.Ident:
					if dropped[n.Name] {
						problems = append(problems, &Error{Column: g.columnKey(f), Err: fmt.Errorf("%w: %sFields needs %s, which sqlc-gen-go leaves out because no query uses it; give the column a go_type override, write a query that reads the column, or turn omit_unused_structs off", ErrDroppedType, m.Name, g.ref(n.Name))})
					}
				}

				return true
			})
		}
	}

	return errors.Join(problems...)
}

func (g *generator) model(m gengo.Struct) error {
	table := m.Table.GetName()
	fieldsVar := m.Name + "Fields"
	declaration := lowerFirst(m.Name) + "Declaration"
	if err := g.declare(m.Name, fieldsVar); err != nil {
		return err
	}
	var encrypted []gengo.Field
	types := make([]string, len(m.Fields))
	for i, f := range m.Fields {
		c := g.column(f)
		if c == nil {
			typ, err := g.fieldType(m.Name, f)
			if err != nil {
				return err
			}
			types[i] = "Column[" + typ + "]"

			continue
		}
		types[i] = c.Type.GoName + "Field"
		encrypted = append(encrypted, f)
	}

	g.printf("// %s has a value for each column of %s.\n", fieldsVar, table)
	g.printf("var %s = struct {\n", fieldsVar)
	for i, f := range m.Fields {
		g.printf("\t%s %s\n", f.Name, types[i])
	}
	g.printf("}{\n")
	for i, f := range m.Fields {
		c := g.column(f)
		if c == nil {
			g.printf("\t%s: %s{%q, %q},\n", f.Name, types[i], table, f.Column.GetName())

			continue
		}
		null := `""`
		if c.Nullable {
			null = "gensupport.NullSQL"
		}
		g.printf("\t%s: newField[%s](%s, %q, %q, %q, %s),\n", f.Name, types[i], declaration, table, c.Name, c.Type.Name, null)
	}
	g.printf("}\n\n")

	if len(encrypted) == 0 {
		return nil
	}
	if err := g.declare(m.Name, declaration); err != nil {
		return err
	}
	cols := make([]codecColumn, len(encrypted))
	for i, f := range encrypted {
		c := g.column(f)
		cols[i] = codecColumn{column: c, nullable: c.Nullable}
	}
	g.printf("var %s = %s\n\n", declaration, declarationExpr(table, cols))

	return nil
}

func lowerFirst(s string) string {
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])

	return string(r)
}
