// Package genstash is sqlc-gen-stash's generator. Generate is the plugin:
// it writes a Go package, as sqlc-gen-go does, and CipherStash encryption
// code for it. sqlc runs it through the sqlc-gen-stash command, and a
// plugin of another author can call it in code.
package genstash

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
	"github.com/cipherstash/stack/languages/golang/stashgen"
	"github.com/sqlc-dev/plugin-sdk-go/plugin"
	"golang.org/x/mod/modfile"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/gengo"
)

const eqlImport = "github.com/cipherstash/stack/languages/golang/encrypt/eql"

// encryptedColumn is a table column whose type is an EQL v4 domain.
type encryptedColumn struct {
	// Key is how the column is named in sqlc's column overrides:
	// table.column, or schema.table.column outside the default schema.
	Key string
	// Table is the unqualified table name, which is the encryption context.
	Table string
	// Name is the column name, the field's name in the declaration.
	Name string
	// Identity is the field's encryption identity.
	Identity string
	Type     eql.Type
	// Nullable says the column can be NULL, which is how it stores nil.
	Nullable bool
	// Operators are the operators the engine answers on the column, one
	// query method each.
	Operators []stashgen.Operator
}

// Generate is the plugin: it writes sqlc-gen-go's package for req and, in
// a folder inside it, the <package>stash package. When it refuses req's
// options, schema or queries, the error it returns holds an *Error for each
// problem: errors.Is tells it from the Err sentinels, errors.AsType returns
// the first *Error, and the problems of one check are joined with
// errors.Join.
func Generate(ctx context.Context, req *plugin.GenerateRequest) (*plugin.GenerateResponse, error) {
	resp, err := generate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sqlc-gen-stash: %w", err)
	}

	return resp, nil
}

func generate(ctx context.Context, req *plugin.GenerateRequest) (*plugin.GenerateResponse, error) {
	entry, err := parseOptions(req.GetPluginOptions())
	if err != nil {
		return nil, err
	}
	goOpts, err := gengo.DecodeOptions(entry.Go)
	if err != nil {
		return nil, &Error{Option: "options.go", Err: fmt.Errorf("%w: %w", ErrInvalidOption, err)}
	}
	if err := checkGoOptions(goOpts); err != nil {
		return nil, err
	}
	// sqlc passes the top-level options.<plugin name> on as global options.
	// Their go block goes to sqlc-gen-go as its global options, and their
	// overrides are checked too.
	globalOption := "options." + req.GetSettings().GetCodegen().GetPlugin()
	global, err := parseGlobalOptions(req.GetGlobalOptions(), globalOption)
	if err != nil {
		return nil, err
	}
	globalGo, err := gengo.DecodeGlobalOptions(global.Go)
	if err != nil {
		return nil, &Error{Option: globalOption + ".go", Err: fmt.Errorf("%w: %w", ErrInvalidOption, err)}
	}
	out := req.GetSettings().GetCodegen().GetOut()
	sqlcImport, err := importPath(out)
	if err != nil {
		return nil, err
	}
	views, err := viewNames(req.GetSettings().GetSchema(), req.GetCatalog().GetDefaultSchema())
	if err != nil {
		return nil, err
	}
	columns, err := encryptedColumns(req.GetCatalog(), entry.Stash, views)
	if err != nil {
		return nil, err
	}
	problems := checkOverrides("options.go.overrides", goOpts.Overrides)
	problems = append(problems, checkOverrides(globalOption+".go.overrides", globalGo.Overrides)...)
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	if err := checkQueryParams(req.GetQueries()); err != nil {
		return nil, err
	}

	if req.PluginOptions, err = goOptions(entry.Go, out); err != nil {
		return nil, err
	}
	req.GlobalOptions = global.Go
	pkg, err := gengo.Build(req)
	if err != nil {
		return nil, fmt.Errorf("sqlc-gen-go: %w", err)
	}
	if entry.Stash.EmitTableFields {
		if err := askOperators(ctx, columns); err != nil {
			return nil, err
		}
	}

	files, err := emit(pkg, req.GetCatalog(), views, columns, entry.Stash, sqlcImport)
	if err != nil {
		return nil, err
	}

	return &plugin.GenerateResponse{Files: append(pkg.Files, files...)}, nil
}

// checkGoOptions refuses out, which is the codegen entry's, and a
// sql_package the plugin doesn't generate for.
func checkGoOptions(o *gengo.Options) error {
	if o.Out != "" {
		return &Error{Option: "options.go.out", Err: fmt.Errorf("%w: the codegen entry's out is the package's folder", ErrOutInOptions)}
	}
	switch o.SqlPackage {
	case "", "database/sql", "pgx/v5":
		return nil
	default:
		return &Error{Option: "options.go.sql_package", Err: fmt.Errorf("%w %q: use pgx/v5 or database/sql", ErrUnsupportedSQLPackage, o.SqlPackage)}
	}
}

// goOptions are sqlc-gen-go's options for the package: the codegen entry's
// go block, with out, the package's folder, as sqlc's own gen.go block has
// it, and a db_type override for each EQL type, nullable or not, that gives
// it its encrypt/eql type.
func goOptions(raw json.RawMessage, out string) (json.RawMessage, error) {
	o := map[string]any{}
	var block struct {
		Overrides []any `json:"overrides"`
	}
	if len(raw) > 0 {
		if err := errors.Join(json.Unmarshal(raw, &o), json.Unmarshal(raw, &block)); err != nil {
			return nil, fmt.Errorf("options.go: %w", err)
		}
	}
	o["out"] = out
	overrides := block.Overrides
	for _, dbType := range slices.Sorted(maps.Keys(eqlDBTypes())) {
		for _, nullable := range []bool{false, true} {
			overrides = append(overrides, map[string]any{
				"db_type":  dbType,
				"nullable": nullable,
				"go_type":  map[string]any{"import": eqlImport, "type": eqlGoType(dbType), "pointer": nullable},
			})
		}
	}
	o["overrides"] = overrides

	return json.Marshal(o)
}

// importPath is the import path of the package in dir, a folder relative to
// the directory sqlc runs in: the module path of the nearest go.mod above
// it, followed by dir's path inside that module. dir need not exist yet.
func importPath(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("out: %w", err)
	}
	for mod := abs; ; mod = filepath.Dir(mod) {
		b, err := os.ReadFile(filepath.Join(mod, "go.mod")) //nolint:gosec // the go.mod above the output folder sqlc.yaml names
		if errors.Is(err, fs.ErrNotExist) {
			if filepath.Dir(mod) == mod {
				return "", fmt.Errorf("out: no go.mod above %s to give its package an import path (run sqlc from the directory of sqlc.yaml)", abs)
			}

			continue
		}
		if err != nil {
			return "", fmt.Errorf("out: %w", err)
		}
		modulePath := modfile.ModulePath(b)
		if modulePath == "" {
			return "", fmt.Errorf("out: %s has no module line", filepath.Join(mod, "go.mod"))
		}
		rel, err := filepath.Rel(mod, abs)
		if err != nil {
			return "", err
		}

		return path.Join(modulePath, filepath.ToSlash(rel)), nil
	}
}

// encryptedColumns finds every column of an EQL v4 type in the catalog and
// works out its encryption identity with stash.identity. Each column must be
// a type the SDK produces, must have an identity and must belong to a table,
// not to one of views.
func encryptedColumns(
	catalog *plugin.Catalog,
	stash StashOptions,
	views map[string]bool,
) ([]encryptedColumn, error) {
	var identityPattern *regexp.Regexp
	if stash.Identity != nil {
		// parseOptions has checked the pattern.
		identityPattern = regexp.MustCompile(stash.Identity.Pattern)
	}

	var columns []encryptedColumn
	var problems []error
	for _, s := range catalog.GetSchemas() {
		if s.GetName() == "pg_catalog" || s.GetName() == "information_schema" {
			continue
		}
		for _, t := range s.GetTables() {
			table := t.GetRel().GetName()
			qualified := table
			if s.GetName() != catalog.GetDefaultSchema() {
				qualified = s.GetName() + "." + table
			}
			for _, col := range t.GetColumns() {
				key := qualified + "." + col.GetName()
				typ, isEQL, err := eqlType(catalog.GetDefaultSchema(), col)
				if err != nil {
					problems = append(problems, &Error{Column: key, Err: err})

					continue
				}
				if !isEQL {
					continue
				}
				if views[qualified] {
					// sqlc describes a view like a table, so its columns
					// would be sealed and probed under the view's name, and
					// nothing stored under the table's name would decrypt or
					// match.
					problems = append(problems, &Error{Column: key, Err: fmt.Errorf("%w: %s; read the column from its table", ErrViewColumn, qualified)})

					continue
				}
				identity := ""
				if identityPattern != nil && identityPattern.MatchString(col.GetName()) {
					identity = identityPattern.ReplaceAllString(col.GetName(), stash.Identity.Replacement)
				}
				if identity == "" {
					problems = append(problems, &Error{Column: key, Err: fmt.Errorf("%w: stash.identity.pattern doesn't match it", ErrNoIdentity)})

					continue
				}
				// The SDK checks an identity only on the first Encrypt or
				// Decrypt, so a bad one would generate cleanly and then fail
				// every call. An identity is a plain label segment, and
				// DeclareContextField is the SDK's exported check of one: the
				// same rule, run now. Declaration.Err doesn't check
				// identities.
				if err := gensupport.DeclareContextField(identity).Err(); err != nil {
					problems = append(problems, &Error{Column: key, Err: fmt.Errorf("%w: %q is not a plain label segment: %w", ErrInvalidIdentity, identity, err)})

					continue
				}
				// The SDK validates the context as it builds a declaration;
				// ask it now, so a bad one fails generation.
				d := gensupport.Declare(table).EncryptInto(col.GetName(), gensupport.Kind(typ.Plaintext), typ.Name).Identity(col.GetName(), identity)
				if err := d.Err(); err != nil {
					problems = append(problems, &Error{Column: key, Err: fmt.Errorf("%w: %w", ErrInvalidDeclaration, err)})

					continue
				}
				columns = append(columns, encryptedColumn{Key: key, Table: table, Name: col.GetName(), Identity: identity, Type: typ, Nullable: !col.GetNotNull()})
			}
		}
	}
	problems = append(problems, sharedIdentities(columns)...)
	if len(problems) > 0 {
		slices.SortFunc(problems, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })

		return nil, errors.Join(problems...)
	}

	return columns, nil
}

var (
	lineComment = regexp.MustCompile(`--[^\n]*`)
	// rollback is where a migration's down section starts, in the forms
	// sqlc recognises; sqlc ignores everything after it.
	rollback = regexp.MustCompile(`(?im)^\s*(?:-- \+goose down|-- \+migrate down|---- create above / drop below ----|-- migrate:down)`)
	// createView matches CREATE VIEW in its forms and captures the view's
	// name, possibly schema-qualified and quoted.
	createView = regexp.MustCompile(`(?is)\bcreate\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:recursive\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?((?:"[^"]+"|[\w$]+)(?:\s*\.\s*(?:"[^"]+"|[\w$]+))?)`)
)

// viewNames lists the views the schema files create, named as sqlc's column
// overrides name tables: name in the default schema, schema.name outside it.
// sqlc puts views in the catalog as tables, so this is the only way to tell
// them apart. The paths are the schema setting as sqlc.yaml writes it, read
// the way sqlc reads them: relative to the directory sqlc runs in, which is
// the plugin's too, with a directory standing for the .sql files in it.
func viewNames(paths []string, defaultSchema string) (map[string]bool, error) {
	var files []string
	for _, p := range paths {
		matches := []string{p}
		if strings.ContainsAny(p, "*?[]") {
			var err error
			if matches, err = filepath.Glob(p); err != nil {
				return nil, fmt.Errorf("schema %s: %w", p, err)
			}
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				return nil, fmt.Errorf("reading the schema to find views (run sqlc from the directory of sqlc.yaml): %w", err)
			}
			if !info.IsDir() {
				files = append(files, m)

				continue
			}
			entries, err := os.ReadDir(m)
			if err != nil {
				return nil, fmt.Errorf("reading the schema to find views: %w", err)
			}
			for _, e := range entries {
				files = append(files, filepath.Join(m, e.Name()))
			}
		}
	}

	views := map[string]bool{}
	for _, f := range files {
		base := filepath.Base(f)
		if !strings.HasSuffix(base, ".sql") || strings.HasPrefix(base, ".") || strings.HasSuffix(base, ".down.sql") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // a schema file sqlc.yaml names
		if err != nil {
			return nil, fmt.Errorf("reading the schema to find views: %w", err)
		}
		sql := string(b)
		if loc := rollback.FindStringIndex(sql); loc != nil {
			sql = sql[:loc[0]]
		}
		for _, m := range createView.FindAllStringSubmatch(lineComment.ReplaceAllString(sql, ""), -1) {
			parts := strings.Split(m[1], ".")
			for i, part := range parts {
				part = strings.TrimSpace(part)
				if unquoted, ok := strings.CutPrefix(part, `"`); ok {
					parts[i] = strings.TrimSuffix(unquoted, `"`)
				} else {
					parts[i] = strings.ToLower(part)
				}
			}
			if len(parts) == 2 && parts[0] == defaultSchema {
				parts = parts[1:]
			}
			views[strings.Join(parts, ".")] = true
		}
	}

	return views, nil
}

// eqlType reports whether col's type is an EQL v4 domain and, if so, which
// SDK type it is. An EQL domain the SDK doesn't produce, an EQL array or a
// query domain used as a column type is an error.
func eqlType(defaultSchema string, col *plugin.Column) (eql.Type, bool, error) {
	schema, name := col.GetType().GetSchema(), col.GetType().GetName()
	// sqlc copies a view's column type from the table it reads as one name,
	// so public.eql_v4_text arrives as the name "public.eql_v4_text" with no
	// schema.
	if before, after, ok := strings.Cut(name, "."); ok && schema == "" {
		schema, name = before, after
	}
	if schema == "eql_v4" {
		return eql.Type{}, false, fmt.Errorf("%w: eql_v4.%s", ErrQueryTypeColumn, name)
	}
	if !strings.HasPrefix(name, "eql_v4") {
		return eql.Type{}, false, nil
	}
	if schema != "" && schema != defaultSchema {
		return eql.Type{}, false, fmt.Errorf("%w: %s.%s; the EQL v4 domains are in %s", ErrEQLTypeSchema, schema, name, defaultSchema)
	}
	if col.GetIsArray() {
		return eql.Type{}, false, fmt.Errorf("%w: %s[]", ErrEQLArray, name)
	}
	for _, t := range eql.Types {
		if t.SQLDomain == "public."+name {
			if !t.Producible {
				return eql.Type{}, false, fmt.Errorf("%w: %s (%s): %s", ErrUnproducibleType, name, t.Name, t.Reason)
			}

			return t, true, nil
		}
	}

	return eql.Type{}, false, fmt.Errorf("%w: %s", ErrUnknownEQLType, name)
}

// sharedIdentities refuses two columns of one table with the same identity:
// their declarations would collide.
func sharedIdentities(columns []encryptedColumn) []error {
	seen := map[string]string{}
	var problems []error
	for _, c := range columns {
		key := c.Table + "/" + c.Identity
		if other, ok := seen[key]; ok {
			problems = append(problems, &Error{Column: c.Key, Err: fmt.Errorf("%w %s with %s", ErrSharedIdentity, key, other)})

			continue
		}
		seen[key] = c.Key
	}

	return problems
}

// checkOverrides refuses an override at option, the package's or the
// global ones, for an EQL type, whose override the plugin adds.
func checkOverrides(option string, overrides []gengo.Override) []error {
	var problems []error
	for _, ov := range overrides {
		if eqlDBTypes()[ov.DBType] {
			problems = append(problems, &Error{Option: option, Err: fmt.Errorf("%w: db_type %s, which sqlc-gen-stash gives its encrypt/eql type itself; remove the override", ErrEQLTypeOverride, ov.DBType)})
		}
	}

	return problems
}

// eqlDBTypes are the EQL types the SDK produces, as a db_type override
// names them: each storage domain with and without its schema, and each
// query domain a parameter can be cast to.
func eqlDBTypes() map[string]bool {
	types := map[string]bool{}
	for _, t := range eql.Types {
		if t.Producible {
			types[t.SQLDomain] = true
			types[strings.TrimPrefix(t.SQLDomain, "public.")] = true
		}
	}
	for domain := range queryDomains() {
		types[domain] = true
	}

	return types
}

// eqlGoType is the encrypt/eql type of a db_type: an EQL storage domain,
// with or without its schema, or a query domain.
func eqlGoType(dbType string) string {
	if goName, ok := queryDomains()[dbType]; ok {
		return goName
	}
	for _, t := range eql.Types {
		if t.SQLDomain == dbType || t.SQLDomain == "public."+dbType {
			return t.GoName
		}
	}

	panic("no encrypt/eql type for " + dbType)
}

// queryDomains maps each query domain of an EQL type the SDK produces to its
// Go type in encrypt/eql.
func queryDomains() map[string]string {
	domains := map[string]string{}
	for _, t := range eql.Types {
		if !t.Producible || t.QuerySQLDomain == "" {
			continue
		}
		domains[t.QuerySQLDomain] = stashgen.EQLGoName(t.Query)
		if t.Family == "json_tree" {
			// The operand of a document's Match, which stashgen names the
			// same way.
			domains[t.QuerySQLDomain+"_predicate"] = strings.TrimSuffix(stashgen.EQLGoName(t.Query), "Query") + "PredicateQuery"
		}
	}

	return domains
}

// checkQueryParams refuses a query parameter cast to an eql_v4 type that is
// not the query domain of an EQL type the SDK produces: no query method
// derives its value, and sqlc-gen-go would make it an interface{}.
func checkQueryParams(queries []*plugin.Query) error {
	domains := queryDomains()
	var problems []error
	for _, q := range queries {
		for _, p := range q.GetParams() {
			t := p.GetColumn().GetType()
			if t.GetSchema() != "eql_v4" {
				continue
			}
			if _, ok := domains["eql_v4."+t.GetName()]; !ok {
				problems = append(problems, &Error{Query: q.GetName(), Err: fmt.Errorf("%w: parameter $%d is cast to eql_v4.%s, which isn't the query type of an EQL type this SDK release produces", ErrUnsupportedQueryType, p.GetNumber(), t.GetName())})
			}
		}
	}

	return errors.Join(problems...)
}

// askOperators asks the SDK's engine, as stashgen does, which operators it
// answers on each encrypted column, with one declaration for each table.
func askOperators(ctx context.Context, columns []encryptedColumn) error {
	engine, err := stashgen.GuestEngine(ctx)
	if err != nil {
		return fmt.Errorf("starting the SDK's engine: %w", err)
	}
	if c, ok := engine.(io.Closer); ok {
		defer c.Close()
	}

	byTable := map[string][]int{}
	var tables []string
	for i, c := range columns {
		if _, ok := byTable[c.Table]; !ok {
			tables = append(tables, c.Table)
		}
		byTable[c.Table] = append(byTable[c.Table], i)
	}
	for _, table := range tables {
		d := stashgen.Declaration{Type: table, Context: table}
		for _, i := range byTable[table] {
			c := columns[i]
			f := stashgen.Field{Name: c.Name, GoName: c.Name, GoType: engineGoType(c.Type.Plaintext), Verb: stashgen.VerbEncryptInto, EQLType: c.Type.Name, Identity: c.Identity}
			if c.Nullable {
				f.Null = stashgen.NullSQL
			}
			d.Fields = append(d.Fields, f)
		}
		ops, err := engine.Check(ctx, d)
		if err != nil {
			return err
		}
		for _, i := range byTable[table] {
			columns[i].Operators = ops[columns[i].Name]
		}
	}

	return nil
}

// engineGoType describes the Go type a plaintext kind is generated as
// (plaintextType) to the engine.
func engineGoType(plaintext string) stashgen.GoType {
	switch plaintext {
	case "string":
		return stashgen.GoType{Name: plaintext, Kind: stashgen.KindString, Basic: plaintext}
	case "bool":
		return stashgen.GoType{Name: plaintext, Kind: stashgen.KindBool, Basic: plaintext}
	case "int16", "int32", "int64":
		return stashgen.GoType{Name: plaintext, Kind: stashgen.KindInt, Basic: plaintext}
	case "float32", "float64":
		return stashgen.GoType{Name: plaintext, Kind: stashgen.KindFloat, Basic: plaintext}
	case "date":
		return stashgen.GoType{Name: "encrypt.Date", Kind: stashgen.KindDate}
	case "decimal":
		return stashgen.GoType{Name: "encrypt.Decimal", Kind: stashgen.KindDecimal}
	case "timestamp":
		return stashgen.GoType{Name: "time.Time", Kind: stashgen.KindTimestamp}
	case "json":
		return stashgen.GoType{Name: "json.RawMessage", Kind: stashgen.KindJSON}
	default:
		// encryptedColumns only accepts producible types, which all have a
		// plaintext kind.
		panic("no Go type for the plaintext kind " + plaintext)
	}
}
