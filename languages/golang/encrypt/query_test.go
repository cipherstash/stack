package encrypt_test

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The query fixture holds the guest's query exports to the Rust results:
// packages/stack-encrypt/tests/fixtures/query_operators.json records, for one
// declaration, the term each query by operator derives (each equal to the
// typed Rust query chain's), a page of verified values and a few fetch
// limits. These tests derive, verify and size the same queries through the
// deterministic test build of the guest and compare. Skipped when that build
// is absent.

type queryFixture struct {
	KeySource struct {
		Seed string `json:"seed"`
	} `json:"key_source"`
	Plan    json.RawMessage `json:"plan"`
	Queries []struct {
		Field    string          `json:"field"`
		Operator string          `json:"operator"`
		Input    json.RawMessage `json:"input"`
		Term     struct {
			Operator string          `json:"operator"`
			Fidelity string          `json:"fidelity"`
			Index    string          `json:"index"`
			Domain   *string         `json:"domain"`
			Term     json.RawMessage `json:"term"`
		} `json:"term"`
	} `json:"queries"`
	Verify struct {
		Field    string    `json:"field"`
		Operator string    `json:"operator"`
		Input    string    `json:"input"`
		Values   []*string `json:"values"`
		Verified []bool    `json:"verified"`
	} `json:"verify"`
	TargetLimit []struct {
		Field    string `json:"field"`
		Operator string `json:"operator"`
		Input    string `json:"input"`
		Term     string `json:"term"`
		Want     uint64 `json:"want"`
		Stats    struct {
			Rows       uint64      `json:"rows"`
			Histogram  [][2]uint64 `json:"histogram"`
			Confidence float64     `json:"confidence"`
		} `json:"stats"`
		Limit *uint64 `json:"limit"`
	} `json:"target_limit"`
}

func readQueryFixture(t *testing.T) queryFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "stack-encrypt", "tests", "fixtures", "query_operators.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f queryFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// The terms are derived under queryPlan: a fixture recorded under any
	// other plan fails here, by name, rather than as mismatched bytes.
	var recorded any
	if err := json.Unmarshal(f.Plan, &recorded); err != nil {
		t.Fatal(err)
	}
	if want := wireJSON(queryPlan.Wire()); !reflect.DeepEqual(recorded, want) {
		t.Fatalf("the fixture's plan is not queryPlan; update queryPlan to match it:\nfixture:   %v\nqueryPlan: %v", recorded, want)
	}
	return f
}

// wireJSON is a plan's wire form as encoding/json decodes the same JSON:
// objects as maps, lists as []any.
func wireJSON(v any) any {
	switch v := v.(type) {
	case vcvalue.Object:
		out := make(map[string]any, len(v))
		for _, f := range v {
			out[f.Key] = wireJSON(f.Value)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = wireJSON(item)
		}
		return out
	}
	return v
}

// queryPlan is the fixture's declaration: an email with equality, an age
// with equality and ORE, a name with match, a score with ORE, all under
// users.
var queryPlan = &record.Plan{Context: []string{"users"}, Fields: []record.Field{
	{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality}},
	{Name: "age", Kind: record.Uint32, Outputs: []record.Output{record.Ciphertext, record.Equality, record.Ore}},
	{Name: "name", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Match}},
	{Name: "score", Kind: record.Float64, Outputs: []record.Output{record.Ciphertext, record.Ore}},
}}

func queryFixtureClient(t *testing.T, f queryFixture) *encrypt.Client {
	t.Helper()
	seed, err := hex.DecodeString(f.KeySource.Seed)
	if err != nil || len(seed) != 32 {
		t.Fatalf("seed: %v (%d bytes)", err, len(seed))
	}
	c, err := encrypt.NewDeterministicClient(context.Background(), [32]byte(seed))
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) || errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// goInput is a fixture input as Go code passes it: text as a string, an
// age as the field's uint32, a score as its float64, a range as two of
// them.
func goInput(t *testing.T, field string, raw json.RawMessage) any {
	t.Helper()
	if field == "score" {
		var f float64
		if err := json.Unmarshal(raw, &f); err == nil {
			return f
		}
		var pair [2]float64
		if err := json.Unmarshal(raw, &pair); err != nil {
			t.Fatal(err)
		}
		return []any{pair[0], pair[1]}
	}
	if field != "age" {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	var n uint32
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var pair [2]uint32
	if err := json.Unmarshal(raw, &pair); err != nil {
		t.Fatal(err)
	}
	return []any{pair[0], pair[1]}
}

func fixtureTerms(t *testing.T, raw json.RawMessage) [][]byte {
	t.Helper()
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		b, err := hex.DecodeString(one)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{b}
	}
	var pair []string
	if err := json.Unmarshal(raw, &pair); err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(pair))
	for i, s := range pair {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func TestQueryTermsAreTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	if len(f.Queries) == 0 {
		t.Fatal("the fixture holds no query")
	}
	for _, q := range f.Queries {
		got, err := cipher.QueryTerm(ctx, queryPlan, q.Field, q.Operator, goInput(t, q.Field, q.Input))
		if err != nil {
			t.Fatalf("%s on %s: %v", q.Operator, q.Field, err)
		}
		want := encrypt.QueryTerm{
			Operator: q.Term.Operator,
			Fidelity: record.Fidelity(q.Term.Fidelity),
			Index:    record.Output(q.Term.Index),
			Terms:    fixtureTerms(t, q.Term.Term),
		}
		if q.Term.Domain != nil {
			want.Domain = *q.Term.Domain
		}
		if got.Operator != want.Operator || got.Fidelity != want.Fidelity || got.Index != want.Index || got.Domain != want.Domain || len(got.Terms) != len(want.Terms) {
			t.Fatalf("%s on %s: %+v, want %+v", q.Operator, q.Field, got, want)
		}
		for i := range want.Terms {
			if hex.EncodeToString(got.Terms[i]) != hex.EncodeToString(want.Terms[i]) {
				t.Fatalf("%s on %s: term %d = %x, want %x", q.Operator, q.Field, i, got.Terms[i], want.Terms[i])
			}
		}
	}

	// The engine reads the input as the field's type: a Go int queries a
	// uint32 field as the uint32 it stored.
	asUint32, err := cipher.QueryTerm(ctx, queryPlan, "age", "lt", uint32(40))
	if err != nil {
		t.Fatal(err)
	}
	asInt, err := cipher.QueryTerm(ctx, queryPlan, "age", "lt", 40)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(asInt.Terms[0]) != hex.EncodeToString(asUint32.Terms[0]) {
		t.Fatal("an int input derived another term than the field's uint32")
	}
}

func TestVerifyIsTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	values := make([]any, len(f.Verify.Values))
	for i, v := range f.Verify.Values {
		if v != nil {
			values[i] = *v
		}
	}
	verified, err := c.DefaultKeyset().Verify(context.Background(), queryPlan, f.Verify.Field, f.Verify.Operator, f.Verify.Input, values)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified) != len(f.Verify.Verified) {
		t.Fatalf("Verify = %v, want %v", verified, f.Verify.Verified)
	}
	for i := range verified {
		if verified[i] != f.Verify.Verified[i] {
			t.Fatalf("Verify = %v, want %v", verified, f.Verify.Verified)
		}
	}
	empty, err := c.DefaultKeyset().Verify(context.Background(), queryPlan, "name", "matches", "alice", nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("an empty page: %v %v", empty, err)
	}
}

func TestTargetLimitIsTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	if len(f.TargetLimit) == 0 {
		t.Fatal("the fixture holds no limit")
	}
	for i, l := range f.TargetLimit {
		term, err := hex.DecodeString(l.Term)
		if err != nil {
			t.Fatal(err)
		}
		stats := encrypt.Stats{Rows: l.Stats.Rows, Confidence: l.Stats.Confidence}
		for _, b := range l.Stats.Histogram {
			stats.Histogram = append(stats.Histogram, encrypt.Bucket{Bits: uint32(b[0]), Rows: b[1]})
		}
		got, err := c.DefaultKeyset().TargetLimit(context.Background(), queryPlan, l.Field, l.Operator, term, l.Want, stats)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		rows, bounded := got.Rows()
		switch {
		case l.Limit == nil && bounded:
			t.Fatalf("case %d: %d rows, want unbounded", i, rows)
		case l.Limit != nil && (!bounded || rows != *l.Limit):
			t.Fatalf("case %d: %d (bounded %v), want %d", i, rows, bounded, *l.Limit)
		}
		if l.Limit == nil && got.FetchOr(50) != 50 {
			t.Fatalf("case %d: an unbounded limit fetches the page", i)
		}
	}
}

// A query the field does not answer is refused as a mistyped value is: an
// encoding error that names the field and the rule. The typed path's own
// refusals are term errors.
func TestAQueryTheFieldDoesNotAnswerIsRefused(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	for _, tc := range []struct {
		field, operator string
		input           any
		reason          string
	}{
		{"age", "matches", "ali", "operator_not_answered"},
		{"name", "lt", "ali", "operator_not_answered"},
		{"age", "like", uint32(1), "unknown_operator"},
		{"age", "between", uint32(1), "not_a_range"},
		{"age", "eq", "34", "field_type"},
	} {
		_, err := cipher.QueryTerm(ctx, queryPlan, tc.field, tc.operator, tc.input)
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("%s on %s: %v, want ErrEncoding", tc.operator, tc.field, err)
		}
		var d *encrypt.Diagnostic
		if !errors.As(err, &d) || d.Field() != tc.field || d.Reason() != tc.reason {
			t.Fatalf("%s on %s: %v, want field %q and reason %q", tc.operator, tc.field, err, tc.field, tc.reason)
		}
	}
	// An inverted range is not refused, as SQL's BETWEEN is not.
	if _, err := cipher.QueryTerm(ctx, queryPlan, "age", "between", []any{uint32(65), uint32(18)}); err != nil {
		t.Fatalf("an inverted range: %v", err)
	}
	if _, err := cipher.QueryTerm(ctx, queryPlan, "name", "matches", "al"); !errors.Is(err, encrypt.ErrTerm) {
		t.Fatalf("text that cuts no token: %v, want ErrTerm", err)
	}

	_, err := cipher.Verify(ctx, queryPlan, "email", "eq", "bob@example.com", []any{"bob@example.com"})
	var d *encrypt.Diagnostic
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "exact_operator" {
		t.Fatalf("Verify on an exact operator: %v", err)
	}
	_, err = cipher.TargetLimit(ctx, queryPlan, "age", "lt", []byte{1, 0}, 10, encrypt.Stats{Rows: 1})
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "exact_operator" {
		t.Fatalf("TargetLimit on an exact operator: %v", err)
	}
	_, err = cipher.TargetLimit(ctx, queryPlan, "name", "matches", []byte{1}, 10, encrypt.Stats{Rows: 1})
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "not_a_query_term" {
		t.Fatalf("TargetLimit on half a position: %v", err)
	}
}

// Verifying and sizing use no key, so a guest never given one answers them,
// as it answers the generator's questions.
func TestVerifyAndTargetLimitNeedNoCipher(t *testing.T) {
	wasm, err := encrypt.EmbeddedGuest()
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	c := encrypt.RawClient(t, wasm)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	verified, err := cipher.Verify(ctx, queryPlan, "name", "matches", "alice", []any{"Alice Smith", "Bob"})
	if err != nil || len(verified) != 2 || !verified[0] || verified[1] {
		t.Fatalf("Verify = %v, %v", verified, err)
	}
	limit, err := cipher.TargetLimit(ctx, queryPlan, "name", "matches", []byte{1, 0, 2, 0}, 10, encrypt.Stats{Rows: 100, Histogram: []encrypt.Bucket{{Bits: 10, Rows: 100}}})
	if rows, ok := limit.Rows(); err != nil || !ok || rows < 10 {
		t.Fatalf("TargetLimit = %d %v, %v", rows, ok, err)
	}
	if _, err := cipher.QueryTerm(ctx, queryPlan, "age", "eq", uint32(1)); !errors.Is(err, encrypt.ErrState) {
		t.Fatalf("a query term needs the cipher: %v, want ErrState", err)
	}
}

// The catalog reports, per EQL type, the operators the engine answers:
// TextEq answers eq, exactly, through its equality index, and an ordered type
// the four orderings of one value through its order index, ope or ore_block
// (Between takes a pair, which a type's one query value does not carry), and
// eq too when it also stores an equality term.
func TestTheCatalogListsEachTypesOperators(t *testing.T) {
	wasm, err := encrypt.EmbeddedGuest()
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checker, err := encrypt.NewCheckerOver(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = checker.Close() }()
	targets, err := checker.Targets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Skip("this build holds no EQL types: import encrypt/eql")
	}
	families := []string{"Integer", "Smallint", "Bigint", "Real", "Double", "Date", "Timestamp", "Numeric", "Text"}
	// The index a type answers the orderings through: OPE for Ord and
	// OrdOpe, block ORE for OrdOre.
	orderIndex := map[string]record.Output{}
	for _, family := range families {
		orderIndex[family+"Ord"] = record.Ope
		orderIndex[family+"OrdOpe"] = record.Ope
		orderIndex[family+"OrdOre"] = record.OreBlock
	}
	orderings := func(index record.Output) []record.Operator {
		var ops []record.Operator
		for _, name := range []string{"lt", "lte", "gt", "gte"} {
			ops = append(ops, record.Operator{Name: name, Fidelity: record.Exact, Index: index})
		}
		return ops
	}
	for _, target := range targets {
		index, ordered := orderIndex[target.Name]
		switch {
		case strings.HasSuffix(target.Name, "Eq") && slices.Contains(families, strings.TrimSuffix(target.Name, "Eq")):
			want := []record.Operator{{Name: "eq", Fidelity: record.Exact, Index: record.Equality}}
			if len(target.Operators) != 1 || target.Operators[0] != want[0] {
				t.Fatalf("%s answers %+v, want %+v", target.Name, target.Operators, want)
			}
		case ordered:
			var want []record.Operator
			if strings.HasPrefix(target.Name, "Text") {
				want = append(want, record.Operator{Name: "eq", Fidelity: record.Exact, Index: record.Equality})
			}
			want = append(want, orderings(index)...)
			if !slices.Equal(target.Operators, want) {
				t.Fatalf("%s answers %+v, want %+v", target.Name, target.Operators, want)
			}
		case target.Name == "TextMatch":
			want := record.Operator{Name: "matches", Fidelity: record.Probabilistic, Index: record.Match}
			if len(target.Operators) != 1 || target.Operators[0] != want {
				t.Fatalf("TextMatch answers %+v, want %+v", target.Operators, want)
			}
		case target.Name == "TextSearch" || target.Name == "TextSearchOre":
			// Each through its own index: the query carries that term alone.
			index := record.Ope
			if target.Name == "TextSearchOre" {
				index = record.OreBlock
			}
			want := []record.Operator{{Name: "eq", Fidelity: record.Exact, Index: record.Equality}}
			want = append(want, orderings(index)...)
			want = append(want, record.Operator{Name: "matches", Fidelity: record.Probabilistic, Index: record.Match})
			if !slices.Equal(target.Operators, want) {
				t.Fatalf("%s answers %+v, want %+v", target.Name, target.Operators, want)
			}
		case len(target.Operators) != 0:
			// Every other type is storage-only or not produced.
			t.Fatalf("%s (producible %v) answers %+v, want none", target.Name, target.Producible, target.Operators)
		}
	}
}

// The engine lists the operators each field of a plan answers, with the
// fidelity, arity and index of each: what stashgen writes one method for.
func TestTheCheckerListsAFieldsOperators(t *testing.T) {
	wasm, err := encrypt.EmbeddedGuest()
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checker, err := encrypt.NewCheckerOver(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = checker.Close() }()
	exact := func(name string, index record.Output) record.Operator {
		return record.Operator{Name: name, Fidelity: record.Exact, Index: index}
	}
	for field, want := range map[string][]record.Operator{
		"email": {exact("eq", record.Equality)},
		"age": {
			exact("eq", record.Equality), exact("lt", record.Ore), exact("lte", record.Ore),
			exact("gt", record.Ore), exact("gte", record.Ore),
			{Name: "between", Fidelity: record.Exact, Pair: true, Index: record.Ore},
		},
		"name": {{Name: "matches", Fidelity: record.Probabilistic, Index: record.Match}},
	} {
		got, err := checker.Operators(ctx, queryPlan, field)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s answers %+v, want %+v", field, got, want)
		}
	}
	if _, err := checker.Operators(ctx, queryPlan, "phone"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a field the plan lacks: %v, want ErrEncoding", err)
	}
}

// The generated query methods of Profile, whose declaration is the query
// fixture's, derive the terms the fixture records: one method per operator
// the engine answers, each returning the operator's query type.
func TestGeneratedQueriesAreTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	fields := testusers.QueryProfileFields
	want := func(field, operator string) [][]byte {
		t.Helper()
		for _, q := range f.Queries {
			if q.Field == field && q.Operator == operator {
				return fixtureTerms(t, q.Term.Term)
			}
		}
		t.Fatalf("the fixture has no %s on %s", operator, field)
		return nil
	}
	check := func(name string, got []byte, err error, want []byte) {
		t.Helper()
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s = %x, %v; want %x", name, got, err, want)
		}
	}
	email, err := fields.Email.Eq(ctx, cipher, "bob@example.com")
	check("Email.Eq", email, err, want("email", "eq")[0])
	age, err := fields.Age.Eq(ctx, cipher, 34)
	check("Age.Eq", age, err, want("age", "eq")[0])
	lt, err := fields.Age.Lt(ctx, cipher, 40)
	check("Age.Lt", lt, err, want("age", "lt")[0])
	lte, err := fields.Age.Lte(ctx, cipher, 40)
	check("Age.Lte", lte, err, want("age", "lte")[0])
	gt, err := fields.Age.Gt(ctx, cipher, 18)
	check("Age.Gt", gt, err, want("age", "gt")[0])
	gte, err := fields.Age.Gte(ctx, cipher, 18)
	check("Age.Gte", gte, err, want("age", "gte")[0])
	between, err := fields.Age.Between(ctx, cipher, 18, 65)
	bounds := want("age", "between")
	check("Age.Between low", between.Low, err, bounds[0])
	check("Age.Between high", between.High, err, bounds[1])
	name, err := fields.Name.Matches(ctx, cipher, "alice")
	check("Name.Matches", name.Term(), err, want("name", "matches")[0])
	scoreLt, err := fields.Score.Lt(ctx, cipher, 1.5)
	check("Score.Lt", scoreLt, err, want("score", "lt")[0])
	scoreBetween, err := fields.Score.Between(ctx, cipher, -0.5, 2.5)
	scoreBounds := want("score", "between")
	check("Score.Between low", scoreBetween.Low, err, scoreBounds[0])
	check("Score.Between high", scoreBetween.High, err, scoreBounds[1])
	// A float orders as Postgres's float8 does: -0.0 is 0.0, and NaN sorts
	// last, so a range from NaN is inverted and, as SQL's BETWEEN, matches
	// nothing rather than being refused.
	negZero, err := fields.Score.Lt(ctx, cipher, math.Copysign(0, -1))
	if err != nil {
		t.Fatalf("Score.Lt(-0.0): %v", err)
	}
	zero, err := fields.Score.Lt(ctx, cipher, 0)
	check("Score.Lt(-0.0)", zero, err, negZero)
	fromNaN, err := fields.Score.Between(ctx, cipher, math.NaN(), math.Inf(1))
	if err != nil {
		t.Fatalf("a range from NaN: %v", err)
	}
	if fromNaN.Low.Compare(fromNaN.High) <= 0 {
		t.Errorf("a range from NaN: NaN should order above +Inf")
	}

	// Each query binds as a parameter: driver.Valuer gives the term's bytes.
	for label, v := range map[string]driver.Valuer{"Eq": email, "Lt": lt, "Between.Low": between.Low, "Matches": name} {
		got, err := v.Value()
		if b, ok := got.([]byte); err != nil || !ok || len(b) == 0 {
			t.Errorf("%s.Value() = %T %v", label, got, err)
		}
	}
	// An inverted range is not refused, as SQL's BETWEEN is not.
	if _, err := fields.Age.Between(ctx, cipher, 65, 18); err != nil {
		t.Errorf("an inverted range: %v", err)
	}
}

// A matches query verifies a page of decrypted values in one call, as the
// fixture's page verified, and sizes its fetch as the fixture's limits.
func TestAMatchesQueryVerifiesAndSizesAsTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	q, err := testusers.QueryProfileFields.Name.Matches(ctx, cipher, f.Verify.Input)
	if err != nil {
		t.Fatal(err)
	}
	// A string field has no null: the fixture's null value is left out.
	var page []string
	var verified []bool
	for i, v := range f.Verify.Values {
		if v != nil {
			page = append(page, *v)
			verified = append(verified, f.Verify.Verified[i])
		}
	}
	got, err := q.Verify(ctx, page)
	if err != nil || fmt.Sprint(got) != fmt.Sprint(verified) {
		t.Fatalf("Verify(%q) = %v, %v; want %v", page, got, err, verified)
	}
	if got, err := q.Verify(ctx, nil); err != nil || len(got) != 0 {
		t.Fatalf("an empty page: %v, %v", got, err)
	}
	for i, l := range f.TargetLimit {
		q, err := testusers.QueryProfileFields.Name.Matches(ctx, cipher, l.Input)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(q.Term()) != l.Term {
			t.Fatalf("case %d: Matches(%q) = %x, the fixture's term is %s", i, l.Input, q.Term(), l.Term)
		}
		stats := encrypt.Stats{Rows: l.Stats.Rows, Confidence: l.Stats.Confidence}
		for _, b := range l.Stats.Histogram {
			stats.Histogram = append(stats.Histogram, encrypt.Bucket{Bits: uint32(b[0]), Rows: b[1]})
		}
		limit, err := q.TargetLimit(ctx, l.Want, stats)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		rows, bounded := limit.Rows()
		if (l.Limit == nil) == bounded || (l.Limit != nil && rows != *l.Limit) {
			t.Fatalf("case %d: %d (bounded %v), want %v", i, rows, bounded, l.Limit)
		}
	}
	var zero encrypt.MatchQuery[string]
	if _, err := zero.Value(); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("the zero MatchQuery binds: %v", err)
	}
	var zeroEQL encrypt.EQLMatchQuery[[]byte, string]
	if _, err := zeroEQL.Value(); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("the zero EQLMatchQuery binds: %v", err)
	}
	if _, err := zeroEQL.Verify(ctx, page); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("the zero EQLMatchQuery verifies: %v", err)
	}
	if zero.String() != "encrypt.MatchQuery{}" || zeroEQL.String() != "encrypt.EQLMatchQuery{}" {
		t.Fatalf("the zero queries print as %q and %q", zero.String(), zeroEQL.String())
	}
	// A query with no cipher is an encoding error, from generated code as
	// from the library.
	if _, err := testusers.QueryProfileFields.Name.Matches(ctx, nil, "alice"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("Matches with no cipher: %v", err)
	}
	if _, err := testusers.QueryProfileFields.Email.Eq(ctx, nil, "bob@example.com"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("Eq with no cipher: %v", err)
	}
	if _, err := zero.Verify(ctx, page); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("the zero MatchQuery verifies: %v", err)
	}
	if _, err := zero.TargetLimit(ctx, 10, encrypt.Stats{Rows: 1}); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("the zero MatchQuery sizes a fetch: %v", err)
	}
}

// A matches query holds its text for Verify and never prints it: not
// through fmt with any verb, not through slog.
func TestAMatchesQueryNeverPrintsItsText(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	const text = "zebrafish"
	q, err := testusers.QueryProfileFields.Name.Matches(context.Background(), c.DefaultKeyset(), text)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "%v %+v %#v %s %q %x %d", q, q, q, q, q, q, q)
	// A verb fmt reports as wrong skips Format and prints by reflection, as
	// it does a MatchQuery in an unexported struct field.
	type search struct{ q encrypt.MatchQuery[string] }
	held := search{q: q}
	fmt.Fprintf(&out, " %p %+v %v %#v", q, held, held, held)
	slog.New(slog.NewTextHandler(&out, nil)).Info("query", "q", q, "held", held)
	slog.New(slog.NewJSONHandler(&out, nil)).Info("query", "q", q, "held", held)
	if strings.Contains(out.String(), text) || strings.Contains(out.String(), hex.EncodeToString([]byte(text))) {
		t.Fatalf("the text was printed: %s", out.String())
	}
	if !strings.Contains(out.String(), `field: "name"`) {
		t.Fatalf("the field is not named: %s", out.String())
	}
}
