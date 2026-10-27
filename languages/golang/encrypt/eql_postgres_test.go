package encrypt_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
)

// Rows the Go SDK stores, found by queries the Go SDK derives, inside
// PostgreSQL with EQL v4 installed: the path a program using the SDK runs.
// Every EQL type the engine produces gets a temporary table with one column
// of its domain and five rows: low, middle, middle, high, and a fifth with
// no value. Each query the type answers is derived through the SDK and run
// through EQL's operators, and must find exactly the rows its plaintexts
// say. The values are also read back from the database and opened, since
// PostgreSQL stores jsonb re-serialised.
//
// The fifth row is nil, stored as the engine requires for the type (#1298).
// A type of fixed width with no index or equality alone stores a sealed
// null, as long as a value, which EqNull finds; text and every type with an
// order or match index store SQL NULL, which no query finds.
//
// The list of types is eql.Types, generated from the EQL catalog, so a type
// the engine starts producing is covered here the day it lands. A type whose
// plaintext or index this file has no case for fails rather than being
// skipped.
//
// Skipped unless DATABASE_URL is set. With it set, EQL v4 must be installed
// there: a skip would read the same as a pass. CI installs the bundle built
// from the tree (tests-golang.yml); locally, `mise run go:test:postgres`.

// The four rows' plaintexts for each wire kind, in ascending order with the
// middle two equal. Text is chosen so that only the middle rows share a
// trigram with the match query below.
var (
	eqlInt16s   = [4]int16{-5, 7, 7, 40}
	eqlInt32s   = [4]int32{-5, 7, 7, 40}
	eqlInt64s   = [4]int64{-5_000_000_000, 7, 7, 40_000_000_000}
	eqlFloat32s = [4]float32{-1.5, 2.25, 2.25, 10}
	eqlFloat64s = [4]float64{-1.5, 2.25, 2.25, 10}
	eqlBools    = [4]bool{false, true, true, true}
	eqlStrings  = [4]string{"apple pie", "banana split", "banana split", "cherry tart"}
	eqlMatch    = "banana"
	eqlDates    = [4]encrypt.Date{
		encrypt.DateOf(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
		encrypt.DateOf(time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC)),
		encrypt.DateOf(time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC)),
		encrypt.DateOf(time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC)),
	}
	eqlTimestamps = [4]time.Time{
		time.Date(2020, 1, 1, 8, 0, 0, 0, time.UTC),
		time.Date(2021, 6, 15, 12, 30, 0, 0, time.UTC),
		time.Date(2021, 6, 15, 12, 30, 0, 0, time.UTC),
		time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	eqlDecimals = [4]string{"-1.50", "12.25", "12.25", "400"}
)

// The rows each query must find, by the operator the SDK names it with.
var eqlExpected = map[string][]int{
	"eq":  {2, 3},
	"lt":  {1},
	"lte": {1, 2, 3},
	"gt":  {4},
	"gte": {2, 3, 4},
}

// The SQL operator each SDK query operator is run through. The query
// operand is always on the right; the Rust suite covers it on the left.
var eqlOperators = map[string]string{
	"eq":  "=",
	"lt":  "<",
	"lte": "<=",
	"gt":  ">",
	"gte": ">=",
}

// The queries each index answers, by SDK operator. "match" is not here: it
// is a match query, derived differently, and handled by its own case.
var eqlIndexOperators = map[string][]string{
	"eq":        {"eq"},
	"ope":       {"lt", "lte", "gt", "gte"},
	"ore":       {"lt", "lte", "gt", "gte"},
	"ore_block": {"lt", "lte", "gt", "gte"},
}

func TestEQLTypesRoundTripAndQueryInPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	c := deterministicEQLClient(t)
	cipher := c.DefaultKeyset()
	conn := eqlPostgresConn(t, ctx, url)

	covered := 0
	for _, typ := range eql.Types {
		if !typ.Producible {
			continue
		}
		// A document has operators of its own, not one query per index,
		// so it is not run here or counted: TestJSONDocumentsQueryAndReadInPostgres
		// stores documents through the generated fields (the data plan)
		// into an eql_v4_json_search column and runs every operator there.
		if typ.Plaintext == "json" {
			continue
		}
		covered++
		t.Run(typ.Name, func(t *testing.T) {
			h := eqlHarness{t: t, ctx: ctx, cipher: cipher, conn: conn, typ: typ}
			switch typ.Plaintext {
			case "int16":
				runEQLType(h, gensupport.Int16, eqlInt16s, nil)
			case "int32":
				runEQLType(h, gensupport.Int32, eqlInt32s, nil)
			case "int64":
				runEQLType(h, gensupport.Int64, eqlInt64s, nil)
			case "float32":
				runEQLType(h, gensupport.Float32, eqlFloat32s, nil)
			case "float64":
				runEQLType(h, gensupport.Float64, eqlFloat64s, nil)
			case "bool":
				runEQLType(h, gensupport.Bool, eqlBools, nil)
			case "string":
				runEQLType(h, gensupport.String, eqlStrings, func(f gensupport.Field[string]) ([]byte, error) {
					q, err := gensupport.EQLMatches[[]byte](ctx, f, cipher, eqlMatch)
					return q.Query(), err
				})
			case "date":
				runEQLType(h, gensupport.Date, eqlDates, nil)
			case "timestamp":
				runEQLType(h, gensupport.Timestamp, eqlTimestamps, nil)
			case "decimal":
				var ds [4]encrypt.Decimal
				for i, s := range eqlDecimals {
					d, err := encrypt.ParseDecimal(s)
					if err != nil {
						t.Fatal(err)
					}
					ds[i] = d
				}
				runEQLType(h, gensupport.Decimal, ds, nil)
			default:
				t.Fatalf("no plaintexts for wire kind %q: add a case so %s is tested", typ.Plaintext, typ.Name)
			}
		})
	}
	if covered == 0 {
		t.Fatal("eql.Types lists no producible type, so this test checked nothing")
	}
}

// eqlPostgresConn opens one connection to url, which must have EQL v4
// installed. One connection, because the tests' tables are temporary and
// live in this session.
func eqlPostgresConn(t *testing.T, ctx context.Context, url string) *sql.Conn {
	t.Helper()
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var installed bool
	if err := conn.QueryRowContext(ctx, `SELECT to_regnamespace('eql_v4') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("EQL v4 is not installed in DATABASE_URL: install the bundle built from the tree (`mise run build` in packages/eql writes release/cipherstash-encrypt-v4.sql), or run `mise run go:test:postgres`")
	}
	return conn
}

type eqlHarness struct {
	t      *testing.T
	ctx    context.Context
	cipher *encrypt.Cipher
	conn   *sql.Conn
	typ    eql.Type
}

// runEQLType stores the four values in a column of typ's domain, runs every
// query typ's indexes answer, and opens what the database hands back.
// match derives the match query for a type with the match index.
func runEQLType[T comparable](h eqlHarness, kind gensupport.Kind, values [4]T, match func(gensupport.Field[string]) ([]byte, error)) {
	t, ctx, typ := h.t, h.ctx, h.typ
	t.Helper()
	sealedNull := eqlSealsNull(typ)
	mode, notNull := gensupport.NullSQL, ""
	if sealedNull {
		mode, notNull = gensupport.NullSealed, " NOT NULL"
	}
	decl := gensupport.Declare("go_eql_postgres").Passthrough("id").EncryptInto("v", kind, typ.Name).Null("v", mode)
	if err := decl.Err(); err != nil {
		t.Fatal(err)
	}
	field := gensupport.NewField[T](decl, "v")
	table := "go_eql_" + strings.ToLower(typ.Name)
	nullRow := len(values) + 1

	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := h.conn.ExecContext(ctx, stmt, args...); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec(fmt.Sprintf(`CREATE TEMPORARY TABLE %s (id int PRIMARY KEY, v %s%s)`, table, typ.SQLDomain, notNull))
	t.Cleanup(func() { _, _ = h.conn.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+table) })

	insert := fmt.Sprintf(`INSERT INTO %s VALUES ($1, $2::text::jsonb::%s)`, table, typ.SQLDomain)
	var first []byte
	for i, v := range values {
		out, err := field.Encrypt(ctx, h.cipher, v)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = out.EQL
		}
		exec(insert, i+1, string(out.EQL))
	}
	if sealedNull {
		out, err := field.EncryptNull(ctx, h.cipher)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := eqlCiphertextLen(t, out.EQL), eqlCiphertextLen(t, first); got != want {
			t.Errorf("a sealed null's c is %d characters, a value's %d: the column shows which rows are absent", got, want)
		}
		exec(insert, nullRow, string(out.EQL))
	} else {
		exec(insert, nullRow, nil)
	}

	ids := func(where string, args ...any) ([]int, error) {
		rows, err := h.conn.QueryContext(ctx, fmt.Sprintf(`SELECT id FROM %s WHERE %s ORDER BY id`, table, where), args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var found []int
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			found = append(found, id)
		}
		return found, rows.Err()
	}
	operand := "$1::text::jsonb::" + typ.QuerySQLDomain

	answered := map[string]bool{}
	for _, index := range typ.Indexes {
		if index == "match" {
			if match == nil {
				t.Fatalf("%s has the match index but %s is not text", typ.Name, typ.Plaintext)
			}
			sf := gensupport.NewField[string](decl, "v")
			q, err := match(sf)
			if err != nil {
				t.Fatal(err)
			}
			found, err := ids("v @@ "+operand, string(q))
			if err != nil {
				t.Fatalf("match: %v", err)
			}
			if !slices.Equal(found, []int{2, 3}) {
				t.Errorf("v @@ match(%q) found rows %v, want [2 3]", eqlMatch, found)
			}
			continue
		}
		operators, ok := eqlIndexOperators[index]
		if !ok {
			t.Fatalf("no query for the %q index: add one so %s is tested", index, typ.Name)
		}
		for _, op := range operators {
			if answered[op] {
				continue
			}
			answered[op] = true
			term, err := field.Term(ctx, h.cipher, op, values[1])
			if err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			found, err := ids(fmt.Sprintf("v %s %s", eqlOperators[op], operand), string(term))
			if err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			if want := eqlExpected[op]; !slices.Equal(found, want) {
				t.Errorf("v %s middle found rows %v, want %v", eqlOperators[op], found, want)
			}
		}
	}

	// The nil row: a sealed null is the one row EqNull finds, and SQL NULL
	// is the one row IS NULL finds. No query above found it.
	if sealedNull && answered["eq"] {
		term, err := field.NullTerm(ctx, h.cipher, "eq")
		if err != nil {
			t.Fatalf("eq of nil: %v", err)
		}
		found, err := ids("v = "+operand, string(term))
		if err != nil {
			t.Fatalf("eq of nil: %v", err)
		}
		if !slices.Equal(found, []int{nullRow}) {
			t.Errorf("v = EqNull found rows %v, want [%d]", found, nullRow)
		}
	}
	found, err := ids("v IS NULL")
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{nullRow}; sealedNull {
		if len(found) != 0 {
			t.Errorf("a sealed null is a value, but IS NULL found rows %v", found)
		}
	} else if !slices.Equal(found, want) {
		t.Errorf("IS NULL found rows %v, want %v", found, want)
	}

	// What the type does not answer, PostgreSQL refuses rather than
	// comparing the stored jsonb. A storage-only type has no query domain,
	// so it is compared with itself.
	switch {
	case len(typ.Indexes) == 0:
		expectRefused(t, h.conn, ctx, fmt.Sprintf(`SELECT id FROM %s WHERE v = v`, table), "=", typ.SQLDomain)
	case !answered["lt"]:
		expectRefused(t, h.conn, ctx, fmt.Sprintf(`SELECT id FROM %s WHERE v < v`, table), "<", typ.SQLDomain)
	}

	// Read back what PostgreSQL stored, and open it.
	rows, err := h.conn.QueryContext(ctx, fmt.Sprintf(`SELECT v::text FROM %s ORDER BY id`, table))
	if err != nil {
		t.Fatal(err)
	}
	var stored []gensupport.Record
	for rows.Next() {
		var text sql.NullString
		if err := rows.Scan(&text); err != nil {
			t.Fatal(err)
		}
		rec := gensupport.Record{"id": {Value: int32(len(stored) + 1)}}
		if text.Valid {
			// SQL NULL leaves the field out, as a generated type does.
			rec["v"] = gensupport.Output{EQL: []byte(text.String)}
		}
		stored = append(stored, rec)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := eqlCodec(decl).Decrypt(ctx, h.cipher, stored)
	if err != nil {
		t.Fatal(err)
	}
	// A short read or a short decrypt would otherwise check fewer rows.
	if len(opened) != nullRow {
		t.Fatalf("read back and opened %d rows, want %d", len(opened), nullRow)
	}
	if got, err := gensupport.GetPtr[T](opened[nullRow-1], "v"); err != nil || got != nil {
		t.Errorf("the nil row opened as %v, %v; want nil", got, err)
	}
	for i, vals := range opened[:len(values)] {
		got, err := gensupport.Get[T](vals, "v")
		if err != nil {
			t.Fatal(err)
		}
		if !eqlSame(got, values[i]) {
			t.Errorf("row %d opened as %v, want %v", i+1, got, values[i])
		}
	}
}

// eqlSealsNull says whether typ stores nil as a sealed null, as stashgen
// would choose for it: a plaintext of fixed width, not text, and no index
// but equality, since a null has an equality term and no other.
func eqlSealsNull(typ eql.Type) bool {
	if typ.Plaintext == "string" {
		return false
	}
	for _, index := range typ.Indexes {
		if index != "eq" {
			return false
		}
	}
	return true
}

// eqlCiphertextLen is the length of the `c` an EQL value stores.
func eqlCiphertextLen(t *testing.T, value []byte) int {
	t.Helper()
	var envelope struct {
		C string `json:"c"`
	}
	if err := json.Unmarshal(value, &envelope); err != nil || envelope.C == "" {
		t.Fatalf("the EQL value has no c: %v: %s", err, value)
	}
	return len(envelope.C)
}

// eqlCodec opens records of one declaration without a generated type: the
// record is the encrypted form and the values map the plaintext one.
func eqlCodec(decl gensupport.Declaration) *gensupport.Codec[gensupport.Values, gensupport.Record] {
	return gensupport.New(gensupport.Generated[gensupport.Values, gensupport.Record]{
		TypeName:    "GoEQLPostgres",
		Declaration: decl,
		Source:      func(v gensupport.Values) gensupport.Values { return v },
		Seal:        func(r gensupport.Record) (gensupport.Record, error) { return r, nil },
		Open:        func(r gensupport.Record) gensupport.Record { return r },
		Value:       func(_ gensupport.Record, v gensupport.Values) (gensupport.Values, error) { return v, nil },
	})
}

// eqlSame compares two plaintexts, decimals by value rather than by their
// internal representation.
func eqlSame[T comparable](a, b T) bool {
	if da, ok := any(a).(encrypt.Decimal); ok {
		return da.String() == any(b).(encrypt.Decimal).String()
	}
	return a == b
}

// expectRefused runs query and wants EQL's own refusal of operator on
// domain, not some other error that happens to stop the query.
func expectRefused(t *testing.T, conn *sql.Conn, ctx context.Context, query, operator, domain string) {
	t.Helper()
	rows, err := conn.QueryContext(ctx, query)
	if err == nil {
		err = rows.Close()
	}
	want := fmt.Sprintf("operator %s is not supported for %s", operator, domain)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || !strings.Contains(pgErr.Message, want) {
		t.Errorf("%s: want PostgreSQL to refuse it with %q, got %v", query, want, err)
	}
}
