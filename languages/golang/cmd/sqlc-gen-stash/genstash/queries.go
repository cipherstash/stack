package genstash

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/gengo"
)

type queryMethodsOptions struct {
	EncryptParams  bool
	DecryptResults bool
}

// queryMethods adds a wrapper around sqlc's Queries. Unchanged methods are
// promoted from that struct; converted methods shadow them.
func (g *generator) queryMethods(pkg *gengo.Package, opts queryMethodsOptions, structs map[string]*gengo.Struct) error {
	if !opts.EncryptParams && !opts.DecryptResults {
		return nil
	}
	if err := g.declare("query methods", "CipherLookuper", "Queries", "New"); err != nil {
		return err
	}
	g.printf(`// CipherLookuper returns the cipher for a query's context, or an error saying
// why there is none.
type CipherLookuper func(context.Context) (*encrypt.Cipher, error)

// Queries wraps sqlc's Queries. It neither starts transactions nor retries queries.
// Methods without conversions are promoted; the original methods remain available
// explicitly through Queries.
type Queries struct {
	*%s.Queries
	lookuper CipherLookuper
}

// New uses lookuper for each converted query, never retaining a tenant's
// cipher between calls.
// A lookup error or a nil cipher prevents SQL execution.
`, g.sqlcPkg)
	dbParam, dbArg := "dbtx "+g.ref("DBTX")+", ", "dbtx"
	if g.opts.EmitMethodsWithDbArgument {
		dbParam, dbArg = "", ""
	}
	g.printf(`func New(%slookuper CipherLookuper) *Queries {
	return &Queries{Queries: %s.New(%s), lookuper: lookuper}
}

`, dbParam, g.sqlcPkg, dbArg)
	if !g.opts.EmitMethodsWithDbArgument {
		txType := "*sql.Tx"
		if g.opts.SqlPackage == "pgx/v5" {
			txType = "pgx.Tx"
		}
		g.printf(`// WithTx binds the queries to tx, preserving automatic conversion and cipher lookup.
func (q *Queries) WithTx(tx %s) *Queries {
	return &Queries{Queries: q.Queries.WithTx(tx), lookuper: q.lookuper}
}

`, txType)
	}
	if g.opts.EmitPreparedQueries && g.opts.SqlPackage != "pgx/v5" {
		if err := g.declare("query methods", "Prepare"); err != nil {
			return err
		}
		g.printf(`// Prepare prepares sqlc's queries and wraps them with automatic conversion.
func Prepare(ctx context.Context, dbtx %s.DBTX, lookuper CipherLookuper) (*Queries, error) {
	q, err := %s.Prepare(ctx, dbtx)
	if err != nil { return nil, err }
	return &Queries{Queries: q, lookuper: lookuper}, nil
}

`, g.sqlcPkg, g.sqlcPkg)
	}
	g.printf(`
func (q *Queries) cipher(ctx context.Context) (*encrypt.Cipher, error) {
	c, err := q.lookuper(ctx)
	if err != nil { return nil, fmt.Errorf("look up cipher: %%w", err) }
	if c == nil { return nil, fmt.Errorf("look up cipher: nil cipher") }
	return c, nil
}

`)
	if opts.DecryptResults {
		if err := g.declare("query methods", "ResultDecryptionError"); err != nil {
			return err
		}
		g.printf(`// ResultDecryptionError means SQL succeeded but its result could not be decrypted.
// A write may already be committed: do not assume it is safe to retry.
type ResultDecryptionError struct {
	Query string
	Err error
}

func (e *ResultDecryptionError) Error() string { return fmt.Sprintf("%%s: decrypt result: %%v", e.Query, e.Err) }
func (e *ResultDecryptionError) Unwrap() error { return e.Err }

`)
	}
	for _, q := range pkg.Queries {
		seal, open := false, false
		var err error
		if opts.EncryptParams {
			seal, err = g.queryValueEncrypted(q.Arg, structs)
			if err != nil {
				return &Error{Query: q.MethodName, Err: err}
			}
		}
		returnsRows := q.Cmd == ":one" || q.Cmd == ":many" || q.Cmd == ":batchone" || q.Cmd == ":batchmany"
		if opts.DecryptResults && returnsRows {
			open, err = g.queryValueEncrypted(q.Ret, structs)
			if err != nil {
				return &Error{Query: q.MethodName, Err: err}
			}
		}
		if seal || open {
			if err := g.queryMethod(q, queryMethodsOptions{EncryptParams: seal, DecryptResults: open}); err != nil {
				return &Error{Query: q.MethodName, Err: err}
			}
		}
	}

	return nil
}

func (g *generator) queryValueEncrypted(v gengo.QueryValue, structs map[string]*gengo.Struct) (bool, error) {
	fields := []gengo.Field{{Type: v.Typ, Column: v.Column}}
	if v.Struct != nil {
		fields = v.Struct.Fields
	}
	encrypted := false
	for _, f := range fields {
		if inner := structs[strings.TrimPrefix(f.Type, "*")]; inner != nil && g.encrypted(inner) {
			return false, fmt.Errorf("%w: converted query methods need encrypted columns listed directly, not sqlc.embed", ErrEncryptedEmbed)
		}
		if g.column(f) != nil {
			if f.Column.GetIsSqlcSlice() {
				return false, fmt.Errorf("%w: sqlc.slice parameters cannot be encrypted automatically", ErrEQLArray)
			}
			encrypted = true
		} else if strings.Contains(f.Type, "eql.") && !strings.HasSuffix(f.Type, "Query") {
			return false, ErrUntraceableField
		}
	}

	return encrypted, nil
}

// plainQueryValueType substitutes a companion struct or a scalar's plaintext type.
func (g *generator) plainQueryValueType(v gengo.QueryValue) string {
	if v.Struct != nil {
		prefix := ""
		if v.IsPointer() {
			prefix = "*"
		}

		return prefix + "Plain" + v.Struct.Name
	}
	f := gengo.Field{Column: v.Column}
	typ := plaintextType(g.column(f))
	if nullable(f) {
		typ = "*" + typ
	}

	return typ
}

type querySignature struct {
	params []string
	args   []string
}

// queryArguments maps sqlc's arguments to the wrapper signature and the
// underlying call, which uses sealed parameters when encryption is enabled.
func (g *generator) queryArguments(q gengo.Query, opts queryMethodsOptions) (querySignature, error) {
	batch := strings.HasPrefix(q.Cmd, ":batch")
	sliceArg := batch || q.Cmd == ":copyfrom"
	if opts.EncryptParams && q.Arg.Struct != nil && !q.Arg.EmitStruct() && !batch {
		return querySignature{}, fmt.Errorf("%w: emit_methods_with_param_encryption needs a parameter struct; set query_parameter_limit: 0", ErrInvalidOption)
	}
	params, args := []string{"ctx context.Context"}, []string{"ctx"}
	if g.opts.EmitMethodsWithDbArgument {
		params = append(params, "dbtx "+g.ref("DBTX"))
		args = append(args, "dbtx")
	}
	if !sliceArg && !opts.EncryptParams {
		for i, arg := range q.Arg.Pairs() {
			typ, err := g.fieldType(q.MethodName, gengo.Field{Type: arg.Type})
			if err != nil {
				return querySignature{}, err
			}
			name := fmt.Sprintf("arg%d", i)
			params = append(params, name+" "+typ)
			args = append(args, name)
		}

		return querySignature{params: params, args: args}, nil
	}
	typ, err := g.fieldType(q.MethodName, gengo.Field{Type: q.Arg.DefineType()})
	if err != nil {
		return querySignature{}, err
	}
	arg := "arg"
	if opts.EncryptParams {
		typ, arg = g.plainQueryValueType(q.Arg), "sealed"
	}
	if sliceArg {
		typ = "[]" + typ
	}

	return querySignature{params: append(params, "arg "+typ), args: append(args, arg)}, nil
}

func (g *generator) queryMethod(q gengo.Query, opts queryMethodsOptions) error {
	if q.MethodName == "Queries" {
		return errors.New("query method Queries conflicts with the wrapped struct")
	}
	arguments, err := g.queryArguments(q, opts)
	if err != nil {
		return err
	}
	ret, err := g.queryReturnType(q, opts)
	if err != nil {
		return err
	}
	signature, fail := "error", "return err"
	if ret != "" {
		signature, fail = "("+ret+", error)", "return zero, err"
	}
	g.printf("// %s converts the opted-in fields and executes the original query.\n", q.MethodName)
	g.printf("func (q *Queries) %s(%s) %s {\n", q.MethodName, strings.Join(arguments.params, ", "), signature)
	if ret != "" {
		g.printf("var zero %s\n", ret)
	}
	g.printf("c, err := q.cipher(ctx)\nif err != nil { %s }\n", fail)
	if opts.EncryptParams {
		if q.Arg.Struct != nil {
			g.printf("sealed, err := Encrypt%s(ctx, c, arg)\nif err != nil { %s }\n", q.Arg.Struct.Name, fail)
		} else {
			if err := g.scalarConversion(q, "Encrypt", "arg", "sealed", fail); err != nil {
				return err
			}
		}
	}
	call := fmt.Sprintf("q.Queries.%s(%s)", q.MethodName, strings.Join(arguments.args, ", "))
	batch := strings.HasPrefix(q.Cmd, ":batch")
	switch {
	case batch && opts.DecryptResults:
		g.printf("return &%sBatchResults{%s, ctx, c}, nil\n", q.MethodName, call)
	case batch:
		g.printf("return %s, nil\n", call)
	case !opts.DecryptResults:
		g.printf("return %s\n", call)
	default:
		g.printf("rows, err := %s\nif err != nil { %s }\n", call, fail)
		if err := g.decryptQueryResult(q, fail); err != nil {
			return err
		}
		g.printf("return plain, nil\n")
	}
	g.printf("}\n\n")
	if batch && opts.DecryptResults {
		return g.queryBatchResults(q)
	}

	return nil
}

func (g *generator) queryReturnType(q gengo.Query, opts queryMethodsOptions) (string, error) {
	switch q.Cmd {
	case ":exec":
		return "", nil
	case ":execrows", ":execlastid", ":copyfrom":
		return "int64", nil
	case ":execresult":
		if g.opts.SqlPackage == "pgx/v5" {
			return "pgconn.CommandTag", nil
		}

		return "sql.Result", nil
	case ":batchone", ":batchmany", ":batchexec":
		name := q.MethodName + "BatchResults"
		if !opts.DecryptResults {
			name = g.ref(name)
		}

		return "*" + name, nil
	case ":one", ":many":
		typ, err := g.fieldType(q.MethodName, gengo.Field{Type: q.Ret.DefineType()})
		if opts.DecryptResults {
			typ = g.plainQueryValueType(q.Ret)
		}
		if q.Cmd == ":many" {
			typ = "[]" + typ
		}

		return typ, err
	default:
		return "", fmt.Errorf("unsupported query command %q", q.Cmd)
	}
}

func (g *generator) decryptQueryResult(q gengo.Query, fail string) error {
	decryptFail := fmt.Sprintf("err = &ResultDecryptionError{Query: %q, Err: err}; %s", q.MethodName, fail)
	if q.Ret.Struct == nil {
		return g.scalarConversion(q, "Decrypt", "rows", "plain", decryptFail)
	}
	many := q.Cmd == ":many" || q.Cmd == ":batchmany"
	rows := "rows"
	if !many {
		typ, err := g.fieldType(q.MethodName, gengo.Field{Type: q.Ret.DefineType()})
		if err != nil {
			return err
		}
		rows = "[]" + typ + "{rows}"
	}
	g.printf("opened, err := Decrypt%s(ctx, c, %s)\nif err != nil { %s }\n", q.Ret.Struct.Name, rows, decryptFail)
	if many {
		g.printf("plain := opened\n")
		if g.opts.EmitEmptySlices {
			g.printf("if plain == nil { plain = []%s{} }\n", g.plainQueryValueType(q.Ret))
		}
	} else {
		g.printf("plain := opened[0]\n")
	}

	return nil
}

// Scalar query arguments and results have no companion struct. Use the same
// column codec directly, batching a slice into one SDK call.
func (g *generator) scalarConversion(q gengo.Query, method, input, output, fail string) error {
	v, from := q.Ret, "Sealed"
	many := q.Cmd == ":many" || q.Cmd == ":batchmany"
	if method == "Encrypt" {
		v, from = q.Arg, "Plain"
		many = strings.HasPrefix(q.Cmd, ":batch") || q.Cmd == ":copyfrom"
	}
	f := gengo.Field{Column: v.Column}
	c := g.codecFor(g.column(f).Table, []gengo.Field{f})
	in, converted := output+"Input", output+"Values"
	if many {
		g.printf("%s := make([]%s%s, len(%s))\nfor i, v := range %s { %s[i].F0 = v }\n", in, c.name, from, input, input, in)
	} else {
		g.printf("%s := []%s%s{{F0: %s}}\n", in, c.name, from, input)
	}
	g.printf("%s, err := %sCodec.%s(ctx, c, %s)\nif err != nil { %s }\n", converted, c.name, method, in, fail)
	if many {
		typ, err := g.fieldType(q.MethodName, gengo.Field{Type: v.DefineType()})
		if err != nil {
			return err
		}
		if method == "Decrypt" {
			typ = g.plainQueryValueType(v)
		}
		g.printf("var %s []%s\nif %s != nil { %s = make([]%s, len(%s)) }\n", output, typ, input, output, typ, converted)
		g.printf("for i, v := range %s { %s[i] = v.F0 }\n", converted, output)
	} else {
		g.printf("%s := %s[0].F0\n", output, converted)
	}

	return nil
}

func (g *generator) queryBatchResults(q gengo.Query) error {
	name := q.MethodName + "BatchResults"
	if err := g.declare(q.MethodName, name); err != nil {
		return err
	}
	plain := g.plainQueryValueType(q.Ret)
	raw, err := g.fieldType(q.MethodName, gengo.Field{Type: q.Ret.DefineType()})
	if err != nil {
		return err
	}
	many := q.Cmd == ":batchmany"
	method := "QueryRow"
	if many {
		method, plain, raw = "Query", "[]"+plain, "[]"+raw
	}
	g.printf("// %s decrypts each query's results and preserves the underlying batch's Close behavior.\n", name)
	g.printf("type %s struct { *%s; ctx context.Context; cipher *encrypt.Cipher }\n", name, g.ref(name))
	g.printf("func (b *%s) %s(f func(int, %s, error)) {\n", name, method, plain)
	g.printf("b.%s.%s(func(i int, rows %s, err error) {\nif f == nil { return }\n", name, method, raw)
	g.printf("var zero %s\nif err != nil { f(i, zero, err); return }\nctx, c := b.ctx, b.cipher\n", plain)
	if err := g.decryptQueryResult(q, "f(i, zero, err); return"); err != nil {
		return err
	}
	g.printf("f(i, plain, nil)\n})\n}\n\n")

	return nil
}
