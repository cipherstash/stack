package encrypt_test

import (
	"cmp"
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"math/big"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
)

// Order through PostgreSQL, over random values. TestEQLTypesRoundTripAndQueryInPostgres
// runs each ordering operator over four fixed values, and a comparator that
// is only partly wrong (one that reads a block ORE term's first blocks, a
// sign bit, or a decimal's scale) still orders most pairs right. Here every
// ordered EQL v4 type gets a temporary table of a few hundred random values
// and the edges of its order, sealed by the Go SDK. Random query values are
// run through `<`, `<=`, `>` and `>=` and must find exactly the rows
// plaintext comparison selects, and ORDER BY on the type's order term must
// put the rows in plaintext order.
//
// Plaintext order is the engine's order key (ADR-0002, and
// stack-encrypt's value module): text by the UTF-8 bytes of its fold, a
// float with -0.0 equal to 0.0 and every NaN one value above +Inf, a
// timestamp to the microsecond (the nanoseconds below it truncated, floor
// on the count since the epoch), and a decimal by value, whatever its scale.
//
// The seed is fixed and logged; EQL_ORDER_SEED replaces it. Each type draws
// from its own generator, seeded from the seed and the type's name, so
// `-run 'TestEQLOrderMatchesPlaintextInPostgres/TextOrdOre'` with the logged
// seed replays one type's values exactly.
//
// Like TestEQLTypesRoundTripAndQueryInPostgres it is skipped without
// DATABASE_URL, and fails when EQL v4 is not installed there.

const (
	eqlOrderSeedEnv     = "EQL_ORDER_SEED"
	eqlOrderDefaultSeed = 1343
	// Random values stored per type, beside the edges and the duplicates.
	eqlOrderRandom = 300
	// Query values per type, beside every edge: random draws, and stored
	// values (so `<=` and `>=` meet ties).
	eqlOrderQueryDraws, eqlOrderQueryStored = 8, 8
	// Rows per INSERT statement.
	eqlOrderBatch = 100
)

// The ordering operators, by SDK name, and what each selects given the
// plaintext comparison of the stored value with the query value.
var eqlOrderOperators = []struct {
	op, sql string
	holds   func(c int) bool
}{
	{"lt", "<", func(c int) bool { return c < 0 }},
	{"lte", "<=", func(c int) bool { return c <= 0 }},
	{"gt", ">", func(c int) bool { return c > 0 }},
	{"gte", ">=", func(c int) bool { return c >= 0 }},
}

// The function that extracts a column's order term, by the index that
// carries it: what an ordered index is built over and ORDER BY sorts by.
// EQL v4 puts no operator class on its domains, so a bare ORDER BY v would
// sort the jsonb.
var eqlOrderExtractors = map[string]string{
	"ope":       "eql_v4.ord_term",
	"ore_block": "eql_v4.ord_term_ore",
}

func TestEQLOrderMatchesPlaintextInPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	seed := uint64(eqlOrderDefaultSeed)
	if s := os.Getenv(eqlOrderSeedEnv); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("%s=%q: %v", eqlOrderSeedEnv, s, err)
		}
		seed = n
	}
	t.Logf("seed %d; replay with %s=%d", seed, eqlOrderSeedEnv, seed)

	ctx := context.Background()
	c := deterministicEQLClient(t)
	cipher := c.DefaultKeyset()
	conn := eqlPostgresConn(t, ctx, url)

	covered := 0
	for _, typ := range eql.Types {
		index := eqlOrderIndex(typ)
		if !typ.Producible || index == "" {
			continue
		}
		covered++
		t.Run(typ.Name, func(t *testing.T) {
			h := eqlHarness{t: t, ctx: ctx, cipher: cipher, conn: conn, typ: typ}
			o := eqlOrder{seed: seed, index: index, r: eqlOrderRand(seed, typ.Name)}
			switch typ.Plaintext {
			case "int16":
				runEQLOrder(h, o, eqlIntOrder[int16](gensupport.Int16, 16))
			case "int32":
				runEQLOrder(h, o, eqlIntOrder[int32](gensupport.Int32, 32))
			case "int64":
				runEQLOrder(h, o, eqlIntOrder[int64](gensupport.Int64, 64))
			case "float32":
				runEQLOrder(h, o, eqlFloat32Order())
			case "float64":
				runEQLOrder(h, o, eqlFloat64Order())
			case "string":
				runEQLOrder(h, o, eqlTextOrder())
			case "date":
				runEQLOrder(h, o, eqlDateOrder())
			case "timestamp":
				runEQLOrder(h, o, eqlTimestampOrder())
			case "decimal":
				runEQLOrder(h, o, eqlDecimalOrder(t))
			default:
				t.Fatalf("no ordered plaintexts for wire kind %q: add a case so %s is tested", typ.Plaintext, typ.Name)
			}
		})
	}
	if covered == 0 {
		t.Fatal("eql.Types lists no producible ordered type, so this test checked nothing")
	}
}

// eqlOrderIndex is the order index typ carries, or "" for none: an index
// that answers `lt` in eqlIndexOperators, the list the round-trip test fails
// without. So an order index added there is tested here too, and fails at
// the extractor until it has one, rather than being skipped.
func eqlOrderIndex(typ eql.Type) string {
	for _, index := range typ.Indexes {
		if slices.Contains(eqlIndexOperators[index], "lt") {
			return index
		}
	}
	return ""
}

// eqlOrderRand is one type's generator: the seed and the type's name, so a
// type's values do not depend on which other types ran.
func eqlOrderRand(seed uint64, name string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return rand.New(rand.NewPCG(seed, h.Sum64()))
}

type eqlOrder struct {
	seed  uint64
	index string
	r     *rand.Rand
}

// eqlOrderGen is how one plaintext kind is drawn and ordered.
type eqlOrderGen[T any] struct {
	kind gensupport.Kind
	// cmp is the engine's plaintext order.
	cmp func(a, b T) int
	// draw draws one value. It may keep state (a pool of shared prefixes,
	// say) so that values that differ only late are drawn together.
	draw func(r *rand.Rand) T
	// edges are stored in every run: the ends of the range, zeros, and
	// neighbours.
	edges []T
	show  func(T) string
}

func runEQLOrder[T any](h eqlHarness, o eqlOrder, g eqlOrderGen[T]) {
	t, ctx, typ := h.t, h.ctx, h.typ
	t.Helper()
	extractor, ok := eqlOrderExtractors[o.index]
	if !ok {
		t.Fatalf("no order term extractor for the %q index: add one so %s is tested", o.index, typ.Name)
	}
	r := o.r

	// The stored values: the edges, the random draws, and thirty of those
	// again, so ties are not left to chance. Shuffled, so a row's id says
	// nothing of its order.
	values := slices.Clone(g.edges)
	for range eqlOrderRandom {
		values = append(values, g.draw(r))
	}
	for range eqlOrderRandom / 10 {
		values = append(values, values[r.IntN(len(values))])
	}
	r.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })

	decl := gensupport.Declare("go_eql_order").Passthrough("id").EncryptInto("v", g.kind, typ.Name)
	if err := decl.Err(); err != nil {
		t.Fatal(err)
	}
	rows := make([]gensupport.Values, len(values))
	for i, v := range values {
		rows[i] = gensupport.Values{"id": int32(i + 1), "v": v}
	}
	sealed, err := eqlCodec(decl).Encrypt(ctx, h.cipher, rows)
	if err != nil {
		t.Fatal(err)
	}

	table := "go_eql_order_" + strings.ToLower(typ.Name)
	if _, err := h.conn.ExecContext(ctx, fmt.Sprintf(`CREATE TEMPORARY TABLE %s (id int PRIMARY KEY, v %s NOT NULL)`, table, typ.SQLDomain)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.conn.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+table) })
	for start := 0; start < len(sealed); start += eqlOrderBatch {
		batch := sealed[start:min(start+eqlOrderBatch, len(sealed))]
		var stmt strings.Builder
		fmt.Fprintf(&stmt, "INSERT INTO %s VALUES ", table)
		args := make([]any, 0, 2*len(batch))
		for i, rec := range batch {
			if i > 0 {
				stmt.WriteString(", ")
			}
			fmt.Fprintf(&stmt, "($%d, $%d::text::jsonb::%s)", 2*i+1, 2*i+2, typ.SQLDomain)
			args = append(args, start+i+1, string(rec["v"].EQL))
		}
		if _, err := h.conn.ExecContext(ctx, stmt.String(), args...); err != nil {
			t.Fatalf("inserting rows %d to %d: %v", start+1, start+len(batch), err)
		}
	}

	ids := func(query string, args ...any) []int {
		t.Helper()
		res, err := h.conn.QueryContext(ctx, query, args...)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		defer res.Close()
		var found []int
		for res.Next() {
			var id int
			if err := res.Scan(&id); err != nil {
				t.Fatal(err)
			}
			found = append(found, id)
		}
		if err := res.Err(); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return found
	}
	replay := fmt.Sprintf("seed %d; replay with %s=%d", o.seed, eqlOrderSeedEnv, o.seed)
	failures := 0
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf(format, args...)
		if failures++; failures == 5 {
			t.Fatalf("%s: stopping after %d disagreements (%s)", typ.Name, failures, replay)
		}
	}

	// Each query value through each operator, against plaintext comparison
	// of every stored value. Every edge is a query value, not a sample of
	// them: the edges hold the ties the order rules make (-0.0 and 0.0, 1.5
	// and 1.50, instants in one microsecond), and an engine that splits a tie
	// shows only in a query on one of the tied values. ORDER BY cannot show
	// it, since plaintext order accepts tied rows in either order.
	queries := slices.Clone(g.edges)
	for range eqlOrderQueryDraws {
		queries = append(queries, g.draw(r))
	}
	for range eqlOrderQueryStored {
		queries = append(queries, values[r.IntN(len(values))])
	}
	field := gensupport.NewField[T](decl, "v")
	for _, q := range queries {
		for _, op := range eqlOrderOperators {
			term, err := field.Term(ctx, h.cipher, op.op, q)
			if err != nil {
				t.Fatalf("%s(%s): %v", op.op, g.show(q), err)
			}
			found := ids(fmt.Sprintf(`SELECT id FROM %s WHERE v %s $1::text::jsonb::%s ORDER BY id`, table, op.sql, typ.QuerySQLDomain), string(term))
			var want []int
			for i, v := range values {
				if op.holds(g.cmp(v, q)) {
					want = append(want, i+1)
				}
			}
			if slices.Equal(found, want) {
				continue
			}
			// The first row the two disagree on names the value pair.
			id, returned := eqlFirstDifference(found, want)
			v := values[id-1]
			if returned {
				fail("%s: v %s q returned row %d, but in plaintext %s %s %s is false (%s)",
					typ.Name, op.sql, id, g.show(v), op.sql, g.show(q), replay)
			} else {
				fail("%s: v %s q missed row %d, but in plaintext %s %s %s is true (%s)",
					typ.Name, op.sql, id, g.show(v), op.sql, g.show(q), replay)
			}
		}
	}

	// ORDER BY the order term, both ways: every row, in plaintext order,
	// so equal values come out next to each other.
	for _, dir := range []string{"ASC", "DESC"} {
		order := ids(fmt.Sprintf(`SELECT id FROM %s ORDER BY %s(v) %s`, table, extractor, dir))
		if len(order) != len(values) {
			t.Fatalf("%s: ORDER BY %s(v) %s returned %d rows, want %d", typ.Name, extractor, dir, len(order), len(values))
		}
		for i := 1; i < len(order); i++ {
			a, b := values[order[i-1]-1], values[order[i]-1]
			c := g.cmp(a, b)
			if (dir == "ASC" && c > 0) || (dir == "DESC" && c < 0) {
				fail("%s: ORDER BY %s(v) %s put row %d (%s) right before row %d (%s), out of plaintext order (%s)",
					typ.Name, extractor, dir, order[i-1], g.show(a), order[i], g.show(b), replay)
				break
			}
		}
	}
}

// eqlFirstDifference is the lowest id in one of two ascending lists and not
// the other, and whether it is in found.
func eqlFirstDifference(found, want []int) (int, bool) {
	i, j := 0, 0
	for i < len(found) && j < len(want) {
		switch {
		case found[i] == want[j]:
			i++
			j++
		case found[i] < want[j]:
			return found[i], true
		default:
			return want[j], false
		}
	}
	if i < len(found) {
		return found[i], true
	}
	return want[j], false
}

// Integers: any bit pattern, small values around zero, values that share
// all but their low six bits (block ORE's last block), and values that
// differ only in one of their top bits (the sign among them).
func eqlIntOrder[I int16 | int32 | int64](kind gensupport.Kind, width uint) eqlOrderGen[I] {
	hi := I(1)<<(width-1) - 1
	lo := -hi - 1
	var bases []I
	draw := func(r *rand.Rand) I {
		if bases == nil {
			for range 4 {
				bases = append(bases, I(r.Uint64())&^63)
			}
		}
		switch r.IntN(4) {
		case 0:
			return I(r.Uint64())
		case 1:
			return I(r.IntN(201) - 100)
		case 2:
			return bases[r.IntN(len(bases))] | I(r.IntN(64))
		default:
			return bases[r.IntN(len(bases))] ^ I(1)<<(width-1-uint(r.IntN(3)))
		}
	}
	edges := []I{lo, lo + 1, -256, -1, 0, 1, 63, 64, 255, 256, hi - 1, hi}
	if width == 64 {
		shift := width / 2 // 32, written so int16 compiles
		edges = append(edges, -I(1)<<shift, I(1)<<shift-1, I(1)<<shift)
	}
	return eqlOrderGen[I]{
		kind: kind, cmp: cmp.Compare[I], draw: draw, edges: edges,
		show: func(v I) string { return strconv.FormatInt(int64(v), 10) },
	}
}

// Floats: any bit pattern, so every exponent is drawn; quarters near zero,
// which tie; and the neighbours of a few values, which differ only in the
// last bit of the mantissa. NaN is ordered (above +Inf, every NaN one
// value), so it is an edge like the others.
func eqlFloat64Order() eqlOrderGen[float64] {
	var bases []float64
	draw := func(r *rand.Rand) float64 {
		if bases == nil {
			for range 4 {
				bases = append(bases, r.NormFloat64()*1e6)
			}
		}
		switch r.IntN(3) {
		case 0:
			return math.Float64frombits(r.Uint64())
		case 1:
			return float64(r.IntN(41)-20) / 4
		default:
			b := bases[r.IntN(len(bases))]
			for range r.IntN(3) {
				b = math.Nextafter(b, math.Inf(1))
			}
			return b
		}
	}
	edges := append(floatValues(), -1, 1, math.Nextafter(1, 0), math.Nextafter(1, 2))
	return eqlOrderGen[float64]{
		kind: gensupport.Float64, cmp: floatOrder[float64], draw: draw, edges: edges,
		show: func(v float64) string { return fmt.Sprintf("%v (bits %#016x)", v, math.Float64bits(v)) },
	}
}

func eqlFloat32Order() eqlOrderGen[float32] {
	var bases []float32
	draw := func(r *rand.Rand) float32 {
		if bases == nil {
			for range 4 {
				bases = append(bases, float32(r.NormFloat64()*1e4))
			}
		}
		switch r.IntN(3) {
		case 0:
			return math.Float32frombits(r.Uint32())
		case 1:
			return float32(r.IntN(41)-20) / 4
		default:
			b := bases[r.IntN(len(bases))]
			for range r.IntN(3) {
				b = math.Nextafter32(b, float32(math.Inf(1)))
			}
			return b
		}
	}
	var edges []float32
	for _, v := range floatValues() {
		edges = append(edges, float32(v))
	}
	edges = append(edges, math.SmallestNonzeroFloat32, -math.SmallestNonzeroFloat32, math.MaxFloat32, -math.MaxFloat32,
		-1, 1, math.Nextafter32(1, 0), math.Nextafter32(1, 2))
	return eqlOrderGen[float32]{
		kind: gensupport.Float32, cmp: floatOrder[float32], draw: draw, edges: edges,
		show: func(v float32) string { return fmt.Sprintf("%v (bits %#08x)", v, math.Float32bits(v)) },
	}
}

// eqlTextAlphabet is foldedAlphabet (characters the fold keeps as they are)
// and the ASCII capitals, whose fold is the ASCII lower case. So the fold
// of a string drawn from it is its ASCII lower case, and eqlTextKey needs
// no Unicode tables.
var eqlTextAlphabet = append([]rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), foldedAlphabet...)

// eqlTextFolds are stored whole, never drawn into a longer string: text
// whose fold drops an accent or expands a letter, and its fold, as
// TestTermOrderIsPlaintextOrder checks the engine gives it.
var eqlTextFolds = map[string]string{
	"caf\u00e9":   "cafe",
	"CAFE":        "cafe",
	"Cafe\u0301":  "cafe",
	"\u00c9lan":   "elan",
	"\u00e9":      "e",
	"e\u0301":     "e",
	"\u00c9":      "e",
	"\u00df":      "ss",
	"stra\u00dfe": "strasse",
	"STRASSE":     "strasse",
}

// eqlTextKey is the engine's order key for a string drawn here: its fold.
func eqlTextKey(s string) string {
	if f, ok := eqlTextFolds[s]; ok {
		return f
	}
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// Text: short random strings with mixed case; shared prefixes of 20, 40
// and 80 characters with a short suffix, so values differ only late; and
// the folds above. The edges add strings either side of block ORE's padding
// buckets (16, 32 and 64 bytes) that differ only in their last byte. Block
// ORE's cost grows with the padded length, about 0.5 ms a byte under the
// test build, so nothing here is near its 1023-byte limit.
func eqlTextOrder() eqlOrderGen[string] {
	str := func(r *rand.Rand, n int) string {
		out := make([]rune, n)
		for i := range out {
			out[i] = eqlTextAlphabet[r.IntN(len(eqlTextAlphabet))]
		}
		return string(out)
	}
	var prefixes []string
	folds := make([]string, 0, len(eqlTextFolds))
	for s := range eqlTextFolds {
		folds = append(folds, s)
	}
	slices.Sort(folds)
	draw := func(r *rand.Rand) string {
		if prefixes == nil {
			for _, n := range []int{20, 40, 80} {
				prefixes = append(prefixes, str(r, n))
			}
		}
		switch n := r.IntN(10); {
		case n < 5:
			return str(r, r.IntN(24))
		case n < 8:
			return prefixes[r.IntN(len(prefixes))] + str(r, r.IntN(4))
		default:
			return folds[r.IntN(len(folds))]
		}
	}
	edges := []string{"", " ", "a", "A", "aa", "ab", "b", "z", "Z", "zz", "\u0436", "\u03c9", "\u4e2d", "~", "0"}
	for _, n := range []int{15, 16, 17, 31, 32, 33, 63, 64, 65} {
		body := strings.Repeat("m", n-1)
		edges = append(edges, body+"a", body+"b")
	}
	return eqlOrderGen[string]{
		kind: gensupport.String,
		cmp: func(a, b string) int {
			return strings.Compare(eqlTextKey(a), eqlTextKey(b))
		},
		draw: draw, edges: edges, show: strconv.Quote,
	}
}

var (
	eqlDateMin = time.Date(-262143, 1, 1, 0, 0, 0, 0, time.UTC)
	eqlDateMax = time.Date(262142, 12, 31, 0, 0, 0, 0, time.UTC)
	// The latest instant a timestamp holds: chrono's.
	eqlTimestampMax = time.Date(262142, 12, 31, 23, 59, 59, 999_999_999, time.UTC)
)

func eqlDateOf(days int64) encrypt.Date {
	return encrypt.DateOf(time.Unix(days*86400, 0).UTC())
}

// Dates: any day in the range, days near the epoch, and runs of
// neighbouring days.
func eqlDateOrder() eqlOrderGen[encrypt.Date] {
	minDay, maxDay := eqlDateMin.Unix()/86400, eqlDateMax.Unix()/86400
	var bases []int64
	draw := func(r *rand.Rand) encrypt.Date {
		if bases == nil {
			for range 4 {
				bases = append(bases, r.Int64N(40_000)-20_000)
			}
		}
		switch r.IntN(3) {
		case 0:
			return eqlDateOf(minDay + r.Int64N(maxDay-minDay+1))
		case 1:
			return eqlDateOf(r.Int64N(80_000) - 40_000)
		default:
			return eqlDateOf(bases[r.IntN(len(bases))] + r.Int64N(5))
		}
	}
	day := func(y int, m time.Month, d int) encrypt.Date { return encrypt.Date{Year: y, Month: m, Day: d} }
	edges := []encrypt.Date{
		encrypt.DateOf(eqlDateMin), encrypt.DateOf(eqlDateMax),
		day(-1, 12, 31), day(0, 1, 1), day(0, 12, 31), day(1, 1, 1),
		day(1969, 12, 31), day(1970, 1, 1), day(1970, 1, 2), day(2000, 2, 29), day(2000, 3, 1),
	}
	return eqlOrderGen[encrypt.Date]{
		kind: gensupport.Date,
		cmp: func(a, b encrypt.Date) int {
			return cmp.Or(cmp.Compare(a.Year, b.Year), cmp.Compare(a.Month, b.Month), cmp.Compare(a.Day, b.Day))
		},
		draw: draw, edges: edges,
		show: func(d encrypt.Date) string { return fmt.Sprintf("%d-%02d-%02d", d.Year, int(d.Month), d.Day) },
	}
}

// eqlMicros is a timestamp's order key: microseconds since the epoch,
// floored, as the engine truncates.
func eqlMicros(t time.Time) int64 {
	return t.Unix()*1_000_000 + int64(t.Nanosecond()/1_000)
}

// Timestamps: any microsecond in the range, microseconds from 1900 to
// 2100, neighbouring microseconds, and instants less than a microsecond
// apart, which tie.
func eqlTimestampOrder() eqlOrderGen[time.Time] {
	minMicro, maxMicro := eqlMicros(eqlDateMin), eqlMicros(eqlTimestampMax)
	at := func(micros, nanos int64) time.Time {
		return time.UnixMicro(micros).Add(time.Duration(nanos)).UTC()
	}
	var bases []int64
	draw := func(r *rand.Rand) time.Time {
		if bases == nil {
			for range 4 {
				bases = append(bases, r.Int64N(6_300_000_000_000_000)-2_200_000_000_000_000)
			}
		}
		switch r.IntN(4) {
		case 0:
			// The span overflows an int64; unsigned arithmetic wraps back.
			return at(minMicro+int64(r.Uint64N(uint64(maxMicro)-uint64(minMicro)+1)), 0)
		case 1:
			return at(r.Int64N(6_300_000_000_000_000)-2_200_000_000_000_000, 0)
		case 2:
			return at(bases[r.IntN(len(bases))]+r.Int64N(4), 0)
		default:
			return at(bases[r.IntN(len(bases))], r.Int64N(1_000))
		}
	}
	epoch := time.Unix(0, 0).UTC()
	edges := []time.Time{
		eqlDateMin, eqlTimestampMax, eqlTimestampMax.Add(-999),
		epoch.Add(-time.Microsecond), epoch.Add(-1), epoch, epoch.Add(999), epoch.Add(time.Microsecond),
		time.Date(2000, 2, 29, 23, 59, 59, 999_999_000, time.UTC),
	}
	return eqlOrderGen[time.Time]{
		kind: gensupport.Timestamp,
		cmp: func(a, b time.Time) int {
			return cmp.Compare(eqlMicros(a), eqlMicros(b))
		},
		draw: draw, edges: edges,
		show: func(t time.Time) string { return t.Format(time.RFC3339Nano) },
	}
}

// The largest decimal mantissa: 2^96 - 1.
var eqlDecimalMaxMantissa = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 96), big.NewInt(1))

// eqlDecimalText writes mantissa * 10^-scale as fixed-point text.
func eqlDecimalText(mantissa *big.Int, scale int, negative bool) string {
	digits := mantissa.String()
	if scale > 0 {
		if len(digits) <= scale {
			digits = strings.Repeat("0", scale+1-len(digits)) + digits
		}
		digits = digits[:len(digits)-scale] + "." + digits[len(digits)-scale:]
	}
	if negative {
		digits = "-" + digits
	}
	return digits
}

// Decimals: any mantissa and scale; small values at small scales, which
// tie across scales (1.5 and 1.50); a few large mantissas and their
// neighbours, which differ only in the last digit; and pooled values again
// with trailing zeros, the same value at a larger scale.
func eqlDecimalOrder(t *testing.T) eqlOrderGen[encrypt.Decimal] {
	parse := func(s string) encrypt.Decimal {
		d, err := encrypt.ParseDecimal(s)
		if err != nil {
			t.Fatalf("ParseDecimal(%q): %v", s, err)
		}
		return d
	}
	type base struct {
		mantissa *big.Int
		scale    int
		negative bool
	}
	var bases []base
	draw := func(r *rand.Rand) encrypt.Decimal {
		if bases == nil {
			for range 4 {
				// 96 bits, with room for the neighbours above it.
				m := eqlRandBits(r, 94)
				m.SetBit(m, 95, 1)
				bases = append(bases, base{m, r.IntN(29), r.IntN(2) == 0})
			}
		}
		switch r.IntN(4) {
		case 0:
			m := eqlRandBits(r, r.IntN(97))
			return parse(eqlDecimalText(m, r.IntN(29), r.IntN(2) == 0))
		case 1:
			return parse(eqlDecimalText(big.NewInt(r.Int64N(4001)), r.IntN(4), r.IntN(2) == 0))
		case 2:
			b := bases[r.IntN(len(bases))]
			return parse(eqlDecimalText(new(big.Int).Add(b.mantissa, big.NewInt(r.Int64N(4))), b.scale, b.negative))
		default:
			// A small value at a scale it does not need.
			m := big.NewInt(r.Int64N(4001))
			scale := r.IntN(4)
			extra := r.IntN(6)
			m.Mul(m, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(extra)), nil))
			return parse(eqlDecimalText(m, scale+extra, r.IntN(2) == 0))
		}
	}
	maxText := eqlDecimalMaxMantissa.String()
	var edges []encrypt.Decimal
	for _, s := range []string{
		"0", "0.00", "-0.000", "1.5", "1.50", "1.500", "-1.5", "-1.50",
		maxText, "-" + maxText,
		eqlDecimalText(eqlDecimalMaxMantissa, 28, false), eqlDecimalText(eqlDecimalMaxMantissa, 28, true),
		eqlDecimalText(new(big.Int).Sub(eqlDecimalMaxMantissa, big.NewInt(1)), 0, false),
		"0.0000000000000000000000000001", "0.0000000000000000000000000002", "-0.0000000000000000000000000001",
	} {
		edges = append(edges, parse(s))
	}
	rat := func(d encrypt.Decimal) *big.Rat {
		v, ok := new(big.Rat).SetString(d.String())
		if !ok {
			t.Fatalf("decimal %s does not read back as a rational", d)
		}
		return v
	}
	return eqlOrderGen[encrypt.Decimal]{
		kind: gensupport.Decimal,
		cmp:  func(a, b encrypt.Decimal) int { return rat(a).Cmp(rat(b)) },
		draw: draw, edges: edges,
		show: func(d encrypt.Decimal) string { return d.String() },
	}
}

// eqlRandBits is a random integer below 2^n, for n at most 128.
func eqlRandBits(r *rand.Rand, n int) *big.Int {
	m := new(big.Int).SetUint64(r.Uint64())
	m.Lsh(m, 64)
	m.Or(m, new(big.Int).SetUint64(r.Uint64()))
	return m.Rsh(m, uint(128-n))
}
