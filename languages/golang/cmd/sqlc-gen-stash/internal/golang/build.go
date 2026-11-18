// Package golang is a copy of sqlc-gen-go's internal package, made by
// copy.sh, with one function of its own: Build, which runs sqlc-gen-go and
// returns what its steps work out on the way to the files as well as the
// files. sqlc-gen-go doesn't export them, so sqlc-gen-stash reads them
// from this copy.
package golang

//go:generate sh copy.sh

import (
	"slices"
	"strings"

	"github.com/sqlc-dev/plugin-sdk-go/plugin"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/internal/golang/opts"
)

// Package is what sqlc-gen-go works out for a package before it runs its
// templates, and the files they write.
type Package struct {
	Options *opts.Options
	// Enums and Structs are the types the package's models file declares.
	Enums   []Enum
	Structs []Struct
	// AllEnums and Tables are every enum and every table's model, before
	// omit_unused_structs leaves any out.
	AllEnums []Enum
	Tables   []Struct
	Queries  []Query
	// Imports maps each import path the package's files use to the name
	// they give it, or "" for none.
	Imports map[string]string
	// Files are the package's files, as sqlc-gen-go writes them.
	Files []*plugin.File
}

// Build runs Generate's steps.
func Build(req *plugin.GenerateRequest) (*Package, error) {
	options, err := opts.Parse(req)
	if err != nil {
		return nil, err
	}
	if err := opts.ValidateOpts(options); err != nil {
		return nil, err
	}
	allEnums := buildEnums(req, options)
	tables := buildStructs(req, options)
	setColumns(req, tables)
	queries, err := buildQueries(req, options, tables)
	if err != nil {
		return nil, err
	}
	// sqlc-gen-go retains scalar parameter columns but drops scalar result
	// columns. Keep their identities for generated result decryption too.
	scalarResults := map[string]*plugin.Column{}
	for _, q := range req.GetQueries() {
		if len(q.GetColumns()) == 1 {
			scalarResults[q.GetName()] = q.GetColumns()[0]
		}
	}
	for i := range queries {
		if queries[i].Ret.Struct == nil {
			queries[i].Ret.Column = scalarResults[queries[i].MethodName]
		}
	}
	enums, structs := allEnums, tables
	if options.OmitUnusedStructs {
		enums, structs = filterUnusedStructs(enums, structs, queries)
	}
	if err := validate(options, enums, structs, queries); err != nil {
		return nil, err
	}

	p := &Package{
		Options:  options,
		Enums:    enums,
		Structs:  structs,
		AllEnums: allEnums,
		Tables:   tables,
		Queries:  queries,
		Imports:  map[string]string{},
	}
	i := &importer{Options: options, Queries: queries, Enums: enums, Structs: structs}
	for _, file := range files(options, queries) {
		p.addImports(i, file)
	}
	// And the imports of a models file with every table's model.
	p.addImports(&importer{Options: options, Queries: queries, Enums: allEnums, Structs: tables}, ModelsFile(options))
	resp, err := generate(req, options, enums, structs, queries)
	if err != nil {
		return nil, err
	}
	p.Files = resp.GetFiles()

	return p, nil
}

// Declared is a struct the package declares, and the file it declares it
// in.
type Declared struct {
	*Struct

	File string
	// Params says the struct is a query's parameters.
	Params bool
	// Batch says the parameters' query takes a slice of them: a :batch* or
	// :copyfrom query.
	Batch bool
}

// Declared lists the structs the package declares, in the order its files
// declare them, files by name.
func (p *Package) Declared() []Declared {
	var structs []Declared
	for i := range p.Structs {
		structs = append(structs, Declared{Struct: &p.Structs[i], File: ModelsFile(p.Options)})
	}
	for _, q := range p.Queries {
		file, batch := QueryFile(p.Options, q), strings.HasPrefix(q.Cmd, ":batch")
		if batch {
			file = BatchFile(p.Options)
		}
		// The batch template declares a query's parameter struct whether or
		// not it is marked to be emitted.
		if q.Arg.Struct != nil && (q.Arg.EmitStruct() || batch) {
			structs = append(structs, Declared{Struct: q.Arg.Struct, File: file, Params: true, Batch: batch || q.Cmd == ":copyfrom"})
		}
		if q.Ret.Struct != nil && q.Ret.EmitStruct() {
			structs = append(structs, Declared{Struct: q.Ret.Struct, File: file})
		}
	}
	slices.SortStableFunc(structs, func(x, y Declared) int { return strings.Compare(x.File, y.File) })

	return structs
}

func (p *Package) addImports(i *importer, file string) {
	for _, group := range i.Imports(file) {
		for _, spec := range group {
			p.Imports[spec.Path] = spec.ID
		}
	}
}

// setColumns sets the Column of each table model's fields, which
// buildStructs leaves nil, as buildQueries sets it on a query's fields:
// buildStructs makes a field for each of the table's columns, in order.
func setColumns(req *plugin.GenerateRequest, structs []Struct) {
	tables := map[string]*plugin.Table{}
	for _, schema := range req.GetCatalog().GetSchemas() {
		for _, table := range schema.GetTables() {
			tables[schema.GetName()+"."+table.GetRel().GetName()] = table
		}
	}
	for _, s := range structs {
		columns := tables[s.Table.GetSchema()+"."+s.Table.GetName()].GetColumns()
		for i := range s.Fields {
			s.Fields[i].Column = columns[i]
		}
	}
}

// files are the files generate writes, by the names importer.Imports takes:
// a query file by its query's source name.
func files(options *opts.Options, queries []Query) []string {
	files := []string{fileName(options.OutputDbFileName, "db.go"), ModelsFile(options)}
	if options.EmitInterface {
		files = append(files, fileName(options.OutputQuerierFileName, "querier.go"))
	}
	if usesCopyFrom(queries) {
		files = append(files, fileName(options.OutputCopyfromFileName, "copyfrom.go"))
	}
	if usesBatch(queries) {
		files = append(files, BatchFile(options))
	}
	seen := map[string]bool{}
	for _, q := range queries {
		if !seen[q.SourceName] {
			seen[q.SourceName] = true
			files = append(files, q.SourceName)
		}
	}

	return files
}

// ModelsFile is the name of the file generate writes the models to.
func ModelsFile(options *opts.Options) string {
	return fileName(options.OutputModelsFileName, "models.go")
}

// BatchFile is the name of the file generate writes the batch queries to.
func BatchFile(options *opts.Options) string {
	return fileName(options.OutputBatchFileName, "batch.go")
}

// QueryFile is the name of the file generate writes the queries of a query
// file to.
func QueryFile(options *opts.Options, q Query) string {
	name := q.SourceName + options.OutputFilesSuffix
	if !strings.HasSuffix(name, ".go") {
		name += ".go"
	}

	return name
}

func fileName(option, name string) string {
	if option != "" {
		return option
	}

	return name
}
