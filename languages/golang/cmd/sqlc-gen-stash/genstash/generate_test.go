package genstash

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sqlc-dev/plugin-sdk-go/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateRefuses checks configurations, schemas and queries that must
// fail generation.
func TestGenerateRefuses(t *testing.T) {
	// noModule is a folder with no go.mod above it. The error names it as
	// filepath.Abs does, which on Windows adds the drive.
	noModule, err := filepath.Abs("/sqlc-gen-stash-test")
	if err != nil {
		t.Fatal(err)
	}
	// users is a catalog with one table, users, of cols. sqlc names each
	// column's table.
	users := func(cols ...*plugin.Column) *plugin.Catalog {
		for _, c := range cols {
			c.Table = &plugin.Identifier{Name: "users"}
		}

		return &plugin.Catalog{
			DefaultSchema: "public",
			Schemas: []*plugin.Schema{{
				Name:   "public",
				Tables: []*plugin.Table{{Rel: &plugin.Identifier{Name: "users"}, Columns: cols}},
			}},
		}
	}
	col := func(name, typ string) *plugin.Column {
		return &plugin.Column{Name: name, Type: &plugin.Identifier{Schema: "public", Name: typ}}
	}
	// queryCol is a column a query returns, read from table, or from no
	// table sqlc can name when table is empty.
	queryCol := func(name, typ, table string) *plugin.Column {
		c := col(name, typ)
		if table != "" {
			c.Table = &plugin.Identifier{Name: table}
		}

		return c
	}
	// getUsers is a query returning cols.
	getUsers := func(cols ...*plugin.Column) []*plugin.Query {
		return []*plugin.Query{{Name: "GetUsers", Cmd: ":many", Filename: "query.sql", Columns: cols}}
	}
	const (
		goOpts   = `"go": {}`
		identity = `"identity": {"pattern": "^(.+_eql4)(?:_eq|_search)?$", "replacement": "$1"}`
	)

	tests := []struct {
		name    string
		catalog *plugin.Catalog
		options string
		global  string
		schema  string // a schema file's contents
		queries []*plugin.Query
		out     string // the codegen entry's out, db when empty
		wantErr error  // the sentinel the error wraps, nil for none
		at      Error  // where the *Error says the problem is
		text    string // what the message must say, when it holds a hint
	}{
		{
			name:    "column the pattern doesn't match",
			catalog: users(col("email", "eql_v4_text")),
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			wantErr: ErrNoIdentity, at: Error{Column: "users.email"},
		},
		{
			name:    "query domain as a column type",
			catalog: users(&plugin.Column{Name: "email_eql4", Type: &plugin.Identifier{Schema: "eql_v4", Name: "query_text_eq"}}),
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			wantErr: ErrQueryTypeColumn, at: Error{Column: "users.email_eql4"},
		},
		{
			name:    "array of an EQL type",
			catalog: users(&plugin.Column{Name: "emails_eql4", IsArray: true, Type: &plugin.Identifier{Schema: "public", Name: "eql_v4_text"}}),
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			wantErr: ErrEQLArray, at: Error{Column: "users.emails_eql4"},
		},
		{
			name:    "identity the SDK would refuse at runtime",
			catalog: users(col("legacy_name", "eql_v4_text")),
			options: `{` + goOpts + `, "stash": {"identity": {"pattern": "^legacy_name$", "replacement": "name/eql4"}}}`,
			wantErr: ErrInvalidIdentity, at: Error{Column: "users.legacy_name"},
		},
		{
			name:    "two columns sharing an identity",
			catalog: users(col("email_eql4", "eql_v4_text"), col("email_eql4_eq", "eql_v4_text_eq")),
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			wantErr: ErrSharedIdentity, at: Error{Column: "users.email_eql4_eq"},
		},
		{
			// Both columns get email_eql4 through a two-group replacement,
			// so they collide.
			name:    "replacement with two groups",
			catalog: users(col("email_eql4", "eql_v4_text"), col("email_eql4_eq", "eql_v4_text_eq")),
			options: `{` + goOpts + `, "stash": {"identity": {"pattern": "^(.+)_(eql4)(?:_eq)?$", "replacement": "${1}_${2}"}}}`,
			wantErr: ErrSharedIdentity, at: Error{Column: "users.email_eql4_eq"},
		},
		{
			name:    "identity without a replacement",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{` + goOpts + `, "stash": {"identity": {"pattern": "^(.+)$"}}}`,
			wantErr: ErrIncompleteIdentity, at: Error{Option: "options.stash.identity"},
		},
		{
			name:    "global override of an EQL type",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			global:  `{"go": {"overrides": [{"db_type": "eql_v4_text", "go_type": "string"}]}}`,
			wantErr: ErrEQLTypeOverride, at: Error{Option: "options.go-stash.go.overrides"},
		},
		{
			// sqlc gives a view's column the type of the table's column as
			// one name, so the view has to be found in the schema files.
			name: "encrypted column of a view",
			catalog: &plugin.Catalog{
				DefaultSchema: "public",
				Schemas: []*plugin.Schema{{
					Name: "public",
					Tables: []*plugin.Table{{
						Rel:     &plugin.Identifier{Name: "user_view"},
						Columns: []*plugin.Column{{Name: "email_eql4", Type: &plugin.Identifier{Name: "public.eql_v4_text"}}},
					}},
				}},
			},
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			schema:  "-- +goose Up\nCREATE OR REPLACE VIEW User_View AS SELECT * FROM users;\n-- +goose Down\nDROP VIEW user_view;\n",
			wantErr: ErrViewColumn, at: Error{Column: "user_view.email_eql4"},
		},
		{
			name:    "parameter cast to an eql_v4 type with no query method",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			queries: []*plugin.Query{{Name: "FindByLeaf", Params: []*plugin.Parameter{{Number: 1, Column: &plugin.Column{Type: &plugin.Identifier{Schema: "eql_v4", Name: "query_json_leaf"}}}}}},
			wantErr: ErrUnsupportedQueryType, at: Error{Query: "FindByLeaf"},
		},
		{
			name:    "unknown option",
			catalog: users(),
			options: `{` + goOpts + `, "stash": {"identity_pattern": "x"}}`,
			wantErr: ErrInvalidOption, at: Error{Option: "options"},
		},
		{
			name:    "query methods with flattened encrypted parameters",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{"go": {"emit_interface": true, "query_parameter_limit": 10}, "stash": {` + identity + `, "emit_methods_with_param_encryption": true}}`,
			queries: []*plugin.Query{{Name: "WriteUser", Cmd: ":exec", Filename: "query.sql", Params: []*plugin.Parameter{
				{Number: 1, Column: queryCol("email_eql4", "eql_v4_text", "users")},
				{Number: 2, Column: queryCol("id", "int4", "users")},
			}}},
			wantErr: ErrInvalidOption, at: Error{Query: "WriteUser"}, text: "query_parameter_limit: 0",
		},
		{
			name:    "query methods with encrypted sqlc.slice parameters",
			catalog: users(col("email_eql4", "eql_v4_text_eq")),
			options: `{` + goOpts + `, "stash": {` + identity + `, "emit_methods_with_param_encryption": true}}`,
			queries: []*plugin.Query{{Name: "FindUsers", Cmd: ":many", Filename: "query.sql", Params: []*plugin.Parameter{
				{Number: 1, Column: &plugin.Column{Name: "email_eql4", IsSqlcSlice: true, Type: &plugin.Identifier{Schema: "public", Name: "eql_v4_text_eq"}, Table: &plugin.Identifier{Name: "users"}}},
			}, Columns: []*plugin.Column{queryCol("id", "int4", "users")}}},
			wantErr: ErrEQLArray, at: Error{Query: "FindUsers"}, text: "sqlc.slice",
		},
		{
			name:    "manual helpers with encrypted sqlc.slice parameters",
			catalog: users(col("email_eql4", "eql_v4_text_eq")),
			options: `{` + goOpts + `, "stash": {` + identity + `}}`,
			queries: []*plugin.Query{{Name: "FindUsers", Cmd: ":many", Filename: "query.sql", Params: []*plugin.Parameter{
				{Number: 1, Column: &plugin.Column{Name: "names", OriginalName: "email_eql4", IsSqlcSlice: true, Type: &plugin.Identifier{Schema: "public", Name: "eql_v4_text_eq"}, Table: &plugin.Identifier{Name: "users"}}},
				{Number: 2, Column: queryCol("id", "int4", "users")},
			}, Columns: []*plugin.Column{queryCol("id", "int4", "users")}}},
			wantErr: ErrEQLArray, at: Error{Field: "FindUsersParams.Names"}, text: "sqlc.slice",
		},
		{
			name:    "query methods decrypting only an encrypted embed",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{"go": {"emit_interface": true}, "stash": {` + identity + `, "emit_methods_with_result_decryption": true}}`,
			queries: getUsers(&plugin.Column{Name: "users", Type: &plugin.Identifier{Name: "users"}, EmbedTable: &plugin.Identifier{Name: "users"}}),
			wantErr: ErrEncryptedEmbed, at: Error{Query: "GetUsers"},
		},
		{
			name:    "language sqlc-gen-stash doesn't generate for",
			catalog: users(),
			options: `{` + goOpts + `, "kotlin": {}}`,
			wantErr: ErrInvalidOption, at: Error{Option: "options"},
		},
		{
			name:    "option sqlc-gen-go doesn't know",
			catalog: users(),
			options: `{"go": {"omit_unused_structz": true}}`,
			wantErr: ErrInvalidOption, at: Error{Option: "options.go"},
		},
		{
			name:    "global options outside go",
			catalog: users(),
			options: `{` + goOpts + `}`,
			global:  `{"overrides": []}`,
			wantErr: ErrInvalidOption, at: Error{Option: "options.go-stash"},
		},
		{
			name:    "out in the Go options",
			catalog: users(),
			options: `{"go": {"out": "db"}}`,
			wantErr: ErrOutInOptions, at: Error{Option: "options.go.out"},
		},
		{
			name:    "out in no Go module",
			catalog: users(),
			options: `{` + goOpts + `}`,
			out:     noModule,
			text:    "no go.mod above " + noModule,
		},
		{
			name:    "override of an EQL type",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{"go": {"overrides": [{"db_type": "public.eql_v4_text", "nullable": true, "go_type": {"import": "github.com/cipherstash/stack/languages/golang/encrypt/eql", "type": "TextEq", "pointer": true}}]}, "stash": {` + identity + `}}`,
			wantErr: ErrEQLTypeOverride, at: Error{Option: "options.go.overrides"},
		},
		{
			// A column read through a CTE, for one.
			name:    "encrypted field sqlc can't trace beside one it can",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{"go": {"emit_interface": true}, "stash": {` + identity + `, "emit_methods_with_result_decryption": true}}`,
			queries: getUsers(queryCol("email_eql4", "eql_v4_text", "users"), queryCol("other", "eql_v4_text", "")),
			wantErr: ErrUntraceableField, at: Error{Field: "GetUsersRow.Other"},
		},
		{
			name:    "sqlc.embed of an encrypted model beside encrypted fields",
			catalog: users(col("email_eql4", "eql_v4_text")),
			options: `{"go": {"emit_interface": true}, "stash": {` + identity + `, "emit_methods_with_result_decryption": true}}`,
			queries: getUsers(queryCol("email_eql4", "eql_v4_text", "users"), &plugin.Column{Name: "users", Type: &plugin.Identifier{Name: "users"}, EmbedTable: &plugin.Identifier{Name: "users"}}),
			wantErr: ErrEncryptedEmbed, at: Error{Field: "GetUsersRow.User"},
		},
		{
			// omit_unused_structs leaves out the enum, which only a table no
			// query returns uses.
			name: "per-column value of a type sqlc-gen-go left out",
			catalog: &plugin.Catalog{
				DefaultSchema: "public",
				Schemas: []*plugin.Schema{{
					Name:  "public",
					Enums: []*plugin.Enum{{Name: "contact_kind", Vals: []string{"email", "phone"}}},
					Tables: []*plugin.Table{
						{Rel: &plugin.Identifier{Name: "contacts"}, Columns: []*plugin.Column{{Name: "kind", NotNull: true, Type: &plugin.Identifier{Schema: "public", Name: "contact_kind"}, Table: &plugin.Identifier{Name: "contacts"}}}},
						{Rel: &plugin.Identifier{Name: "users"}, Columns: []*plugin.Column{col("email_eql4", "eql_v4_text")}},
					},
				}},
			},
			options: `{"go": {"omit_unused_structs": true}, "stash": {"emit_table_fields": true, ` + identity + `}}`,
			wantErr: ErrDroppedType, at: Error{Column: "contacts.kind"},
			text: "ContactFields needs db.ContactKind, which sqlc-gen-go leaves out because no query uses it; give the column a go_type override",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &plugin.GenerateRequest{
				Catalog:       tt.catalog,
				PluginOptions: []byte(tt.options),
				Settings:      &plugin.Settings{Engine: "postgresql", Codegen: &plugin.Codegen{Plugin: "go-stash", Out: cmp.Or(tt.out, "db")}},
				Queries:       tt.queries,
			}
			if tt.schema != "" {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "00001_schema.sql"), []byte(tt.schema), 0o600); err != nil {
					t.Fatal(err)
				}
				req.Settings.Schema = []string{dir}
			}
			if tt.global != "" {
				req.GlobalOptions = json.RawMessage(tt.global)
			}
			_, err := Generate(context.Background(), req)
			if err == nil {
				t.Fatal("Generate() error = nil")
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Generate() error = %v, want it to wrap %v", err, tt.wantErr)
				}
				e, ok := errors.AsType[*Error](err)
				if !ok {
					t.Fatalf("Generate() error = %v, want an *Error", err)
				}
				at := *e
				at.Err = nil
				if at != tt.at {
					t.Errorf("Generate() error at %+v, want %+v", at, tt.at)
				}
			}
			if !strings.Contains(err.Error(), tt.text) {
				t.Errorf("Generate() error = %v, want it to contain %q", err, tt.text)
			}
		})
	}
}

func TestQueryMethodOptions(t *testing.T) {
	cols := []*plugin.Column{
		{Name: "id", NotNull: true, Type: &plugin.Identifier{Name: "int4"}, Table: &plugin.Identifier{Name: "users"}},
		{Name: "email_eql4", Type: &plugin.Identifier{Name: "eql_v4_text"}, Table: &plugin.Identifier{Name: "users"}},
	}
	for _, tt := range []struct {
		name       string
		stash      string
		param      string
		row        string
		sqlPackage string
		cmd        string
		dbArgument bool
		prepared   bool
	}{
		{name: "default"},
		{name: "both off", stash: `"emit_methods_with_param_encryption": false, "emit_methods_with_result_decryption": false,`},
		{name: "encrypt", stash: `"emit_methods_with_param_encryption": true,`, param: "PlainWriteUserParams", row: "*db.User"},
		{name: "decrypt", stash: `"emit_methods_with_result_decryption": true,`, param: "db.WriteUserParams", row: "*PlainUser"},
		{name: "both", stash: `"emit_methods_with_param_encryption": true, "emit_methods_with_result_decryption": true,`, param: "PlainWriteUserParams", row: "*PlainUser"},
		{name: "pgx command tag", stash: `"emit_methods_with_param_encryption": true,`, param: "PlainWriteUserParams", row: "pgconn.CommandTag", cmd: ":execresult"},
		{name: "stdlib result", stash: `"emit_methods_with_param_encryption": true,`, param: "PlainWriteUserParams", row: "sql.Result", sqlPackage: "database/sql", cmd: ":execresult"},
		{name: "pgx db argument", stash: `"emit_methods_with_param_encryption": true,`, param: "PlainWriteUserParams", row: "*db.User", dbArgument: true},
		{name: "stdlib db argument", stash: `"emit_methods_with_param_encryption": true,`, param: "PlainWriteUserParams", row: "*db.User", sqlPackage: "database/sql", dbArgument: true},
		{name: "prepared queries", stash: `"emit_methods_with_param_encryption": true,`, param: "PlainWriteUserParams", row: "*db.User", sqlPackage: "database/sql", prepared: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := &plugin.GenerateRequest{
				Catalog: &plugin.Catalog{DefaultSchema: "public", Schemas: []*plugin.Schema{{
					Name: "public", Tables: []*plugin.Table{{Rel: &plugin.Identifier{Name: "users"}, Columns: cols}},
				}}},
				Settings: &plugin.Settings{Engine: "postgresql", Codegen: &plugin.Codegen{Out: "db"}},
				PluginOptions: []byte(`{"go": {"package": "db", "sql_package": "` + cmp.Or(tt.sqlPackage, "pgx/v5") + `", "emit_methods_with_db_argument": ` + strconv.FormatBool(tt.dbArgument) + `, "emit_prepared_queries": ` + strconv.FormatBool(tt.prepared) + `, "emit_params_struct_pointers": true, "emit_result_struct_pointers": true}, "stash": {` + tt.stash + `
					"identity": {"pattern": "^(.+_eql4)$", "replacement": "$1"}}}`),
				Queries: []*plugin.Query{{Name: "WriteUser", Cmd: cmp.Or(tt.cmd, ":one"), Filename: "query.sql", Columns: cols, Params: []*plugin.Parameter{
					{Number: 1, Column: cols[0]}, {Number: 2, Column: cols[1]},
				}}, {
					Name: "ReadUser", Cmd: ":many", Filename: "query.sql", Columns: []*plugin.Column{
						cols[0],
						{Name: "email", OriginalName: "email_eql4", Type: cols[1].GetType(), Table: cols[1].GetTable()},
					},
				}},
			}
			if tt.cmd == ":execresult" {
				req.Queries[0].Columns = nil
			}
			resp, err := Generate(t.Context(), req)
			require.NoError(t, err)
			var src string
			for _, f := range resp.GetFiles() {
				if f.GetName() == "dbstash/stash.go" {
					src = string(f.GetContents())
				}
			}
			// Manual conversion remains available with any combination of flags.
			assert.Contains(t, src, "type PlainUser struct")
			assert.Contains(t, src, "type PlainReadUserRow struct")
			assert.Contains(t, src, "type PlainWriteUserParams struct")
			assert.Contains(t, src, "func EncryptUser(")
			assert.Contains(t, src, "func DecryptUser(")
			assert.Contains(t, src, "func DecryptReadUserRow(")
			assert.Contains(t, src, "func EncryptWriteUserParams(")
			if tt.param == "" {
				assert.NotContains(t, src, "type Queries struct")
				assert.NotContains(t, src, "func New(")

				return
			}
			assert.Contains(t, src, "func (q *Queries) WriteUser(ctx context.Context,")
			assert.Contains(t, src, fmt.Sprintf("*%s) (%s, error)", tt.param, tt.row))
			if tt.dbArgument {
				assert.Contains(t, src, "func New(lookuper CipherLookuper)")
				assert.Contains(t, src, "WriteUser(ctx context.Context, dbtx db.DBTX,")
				assert.NotContains(t, src, "func (q *Queries) WithTx(")
			} else {
				assert.Contains(t, src, "func New(dbtx db.DBTX, lookuper CipherLookuper)")
				txType := "pgx.Tx"
				if tt.sqlPackage == "database/sql" {
					txType = "*sql.Tx"
				}
				assert.Contains(t, src, "func (q *Queries) WithTx(tx "+txType+") *Queries")
			}
			if tt.prepared {
				assert.Contains(t, src, "func Prepare(ctx context.Context, dbtx db.DBTX, lookuper CipherLookuper)")
			}
		})
	}
}
