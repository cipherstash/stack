package encrypt_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// The fresh cross-language artifact exchange profile: this runner writes
// every value kind at its edges, structural records with index terms (the
// passthrough field stays on the host, as the SDK keeps it), and whole-value
// opaque blobs, as artifacts the Rust runner opens; and it opens the
// artifacts the Rust runner wrote. Decrypted values and derived query terms
// are compared, never ciphertext bytes. See
// conformance/stack-encrypt/exchange-contract.md.
const exchangeProfile = "artifact-exchange-v1"

type exchangeCorpus struct {
	Version              int      `json:"version"`
	Profile              string   `json:"profile"`
	Seed                 string   `json:"seed"`
	RequiredCapabilities []string `json:"required_capabilities"`
	Values               struct {
		Corpus  string   `json:"corpus"`
		Profile string   `json:"profile"`
		Context []string `json:"context"`
		Field   string   `json:"field"`
	} `json:"values"`
	Record struct {
		Context []string        `json:"context"`
		Fields  []exchangeField `json:"fields"`
		Rows    []exchangeRow   `json:"rows"`
	} `json:"record"`
	Blob struct {
		Context []string           `json:"context"`
		Field   string             `json:"field"`
		Cases   []exchangeBlobCase `json:"cases"`
	} `json:"blob"`
	EQL struct {
		Table   string `json:"table"`
		Fixture string `json:"fixture"`
		Schema  string `json:"schema"`
	} `json:"eql"`
}

type exchangeField struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Passthrough bool     `json:"passthrough"`
	Outputs     []string `json:"outputs"`
	Null        string   `json:"null"`
}

type exchangeRow struct {
	ID     string                      `json:"id"`
	Values map[string]conformanceInput `json:"values"`
}

type exchangeBlobCase struct {
	ID    string            `json:"id"`
	Value exchangeBlobValue `json:"value"`
}

// exchangeBlobValue is the blob's shape: the `vc` tags are the field names
// the Rust struct serializes, so a blob is one format whichever wrote it.
type exchangeBlobValue struct {
	Name     string   `json:"name" vc:"name"`
	Age      uint32   `json:"age" vc:"age"`
	Tags     []string `json:"tags" vc:"tags"`
	Nickname *string  `json:"nickname" vc:"nickname"`
}

// sameBlob compares a decoded blob with the corpus value: Go writes a nil
// slice as an empty one and Rust reads either as an empty Vec, so an empty
// tag list is one value however it is spelled.
func sameBlob(got, want exchangeBlobValue) bool {
	if got.Name != want.Name || got.Age != want.Age {
		return false
	}
	if len(got.Tags) != len(want.Tags) || (len(got.Tags) > 0 && !reflect.DeepEqual(got.Tags, want.Tags)) {
		return false
	}
	if (got.Nickname == nil) != (want.Nickname == nil) {
		return false
	}
	return got.Nickname == nil || *got.Nickname == *want.Nickname
}

type exchangeArtifacts struct {
	Version  int                             `json:"version"`
	Profile  string                          `json:"profile"`
	Producer exchangeProducer                `json:"producer"`
	Values   map[string]exchangeStored       `json:"values"`
	Record   map[string]exchangeStoredRecord `json:"record"`
	Blobs    map[string]string               `json:"blobs"`
}

// exchangeProducer says who wrote the artifacts and with what: the SDK,
// the engine it ran, the backend it ran it through, the (fake) key source,
// and the profiles and capabilities the artifacts claim.
type exchangeProducer struct {
	Language   string `json:"language"`
	SDK        string `json:"sdk"`
	SDKVersion string `json:"sdk_version"`
	Backend    string `json:"backend"`
	Engine     struct {
		Name        string  `json:"name"`
		Version     *string `json:"version"`
		GuestSHA256 *string `json:"guest_sha256"`
	} `json:"engine"`
	KeySource struct {
		Kind string `json:"kind"`
		Seed string `json:"seed"`
	} `json:"key_source"`
	Profiles     []string `json:"profiles"`
	Capabilities []string `json:"capabilities"`
	Toolchain    *string  `json:"toolchain"`
}

// exchangeStored is one stored field: the sealed leaf, or none for a SQL
// null, and each index term's bytes.
type exchangeStored struct {
	C     *string           `json:"c"`
	Terms map[string]string `json:"terms"`
}

// exchangeStoredRecord is one stored record: the passthrough fields as the
// typed inputs they carry in the clear, and each sealed field that was
// stored.
type exchangeStoredRecord struct {
	Passthrough map[string]conformanceInput `json:"passthrough"`
	Fields      map[string]exchangeStored   `json:"fields"`
}

func exchangeOutputs(names []string) []record.Output {
	outputs := make([]record.Output, len(names))
	for i, o := range names {
		outputs[i] = record.Output(o)
	}
	return outputs
}

func exchangeValuePlan(corpus *exchangeCorpus, c valueCase) *record.Plan {
	return &record.Plan{Context: corpus.Values.Context, Fields: []record.Field{{
		Name: corpus.Values.Field, Kind: record.Kind(c.Kind), Null: record.Null(c.Null), Outputs: exchangeOutputs(c.Outputs),
	}}}
}

// exchangeRecordPlan is the record's plan as the Go SDK runs it: the sealed
// fields only. A passthrough field never crosses the binding.
func exchangeRecordPlan(corpus *exchangeCorpus) *record.Plan {
	plan := &record.Plan{Context: corpus.Record.Context}
	for _, f := range corpus.Record.Fields {
		if f.Passthrough {
			continue
		}
		plan.Fields = append(plan.Fields, record.Field{Name: f.Name, Kind: record.Kind(f.Kind), Null: record.Null(f.Null), Outputs: exchangeOutputs(f.Outputs)})
	}
	return plan
}

func exchangeBlobPlan(corpus *exchangeCorpus) *record.Plan {
	return &record.Plan{Context: corpus.Blob.Context, Fields: []record.Field{{
		Name: corpus.Blob.Field, Kind: record.Bytes, Outputs: []record.Output{record.Ciphertext},
	}}}
}

func exchangeStoredOf(outputs record.Outputs) exchangeStored {
	c := hex.EncodeToString(outputs.Ciphertext)
	stored := exchangeStored{C: &c, Terms: map[string]string{}}
	for index, term := range outputs.Terms {
		stored.Terms[string(index)] = hex.EncodeToString(term)
	}
	return stored
}

func exchangeOutputsOf(t *testing.T, stored exchangeStored, what string) record.Outputs {
	t.Helper()
	if stored.C == nil {
		t.Fatalf("%s: no ciphertext", what)
	}
	outputs := record.Outputs{Ciphertext: unhexT(t, *stored.C), Terms: map[record.Output][]byte{}}
	for index, term := range stored.Terms {
		outputs.Terms[record.Output(index)] = unhexT(t, term)
	}
	return outputs
}

func unhexT(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exchangeOperator(t *testing.T, index string) string {
	t.Helper()
	switch index {
	case "eq":
		return "eq"
	case "ore", "ope":
		return "lt"
	}
	t.Fatalf("%s: not an index this profile exchanges", index)
	return ""
}

// checkExchangeTerms checks that every stored term is the term this
// runner's own query of the same value derives: the query semantics of the
// artifact, independent of who wrote it. An index the corpus lists as
// unanswered has no operator to compare with, so only its presence is
// checked.
func checkExchangeTerms(t *testing.T, ctx context.Context, cipher *encrypt.Cipher, plan *record.Plan, field string, stored exchangeStored, declared, unanswered []string, input any, equal *conformanceInput, what string) {
	t.Helper()
	if len(stored.Terms) != len(declared)-1 {
		t.Fatalf("%s: stored %d terms for %v", what, len(stored.Terms), declared[1:])
	}
	for _, index := range declared[1:] {
		term, ok := stored.Terms[index]
		if !ok {
			t.Fatalf("%s: no %s term", what, index)
		}
		skip := false
		for _, u := range unanswered {
			skip = skip || u == index
		}
		if skip {
			continue
		}
		probes := []any{input}
		if index == "eq" && equal != nil {
			probes = append(probes, conformanceValue(t, *equal))
		}
		for _, probe := range probes {
			derived, err := cipher.QueryTerm(ctx, plan, field, exchangeOperator(t, index), probe)
			if err != nil || len(derived.Terms) != 1 {
				t.Fatalf("%s: %s: query: %v", what, index, err)
			}
			if hex.EncodeToString(derived.Terms[0]) != term {
				t.Fatalf("%s: %s: the stored term is not the query term", what, index)
			}
		}
	}
}

func exchangePositiveCases(cases []valueCase) []valueCase {
	var positive []valueCase
	for _, c := range cases {
		if c.ExpectedError == nil {
			positive = append(positive, c)
		}
	}
	return positive
}

func exchangeProducerOf(t *testing.T, corpus *exchangeCorpus) exchangeProducer {
	t.Helper()
	guest, err := os.ReadFile(filepath.Join("testdata", "stack_encrypt_guest_deterministic.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(guest)
	guestHash := hex.EncodeToString(sum[:])
	sdk, version := "github.com/cipherstash/stack/languages/golang", "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Path != "" {
			sdk = info.Main.Path
		}
		if info.Main.Version != "" {
			version = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				version += " " + setting.Value
			}
		}
	}
	toolchain := runtime.Version()
	p := exchangeProducer{Language: "go", SDK: sdk, SDKVersion: version, Backend: "wasi", Toolchain: &toolchain}
	p.Engine.Name = "stack-encrypt"
	p.Engine.GuestSHA256 = &guestHash
	p.KeySource.Kind = "deterministic"
	p.KeySource.Seed = corpus.Seed
	p.Profiles = []string{exchangeProfile, corpus.Values.Profile}
	p.Capabilities = corpus.RequiredCapabilities
	return p
}

func produceExchange(t *testing.T, ctx context.Context, cipher *encrypt.Cipher, corpus *exchangeCorpus, values []valueCase) exchangeArtifacts {
	t.Helper()
	out := exchangeArtifacts{
		Version:  1,
		Profile:  exchangeProfile,
		Producer: exchangeProducerOf(t, corpus),
		Values:   map[string]exchangeStored{},
		Record:   map[string]exchangeStoredRecord{},
		Blobs:    map[string]string{},
	}
	for _, c := range exchangePositiveCases(values) {
		plan := exchangeValuePlan(corpus, c)
		input := conformanceValue(t, c.Input)
		sealed, err := cipher.Seal(ctx, plan, []record.Source{{corpus.Values.Field: input}})
		if err != nil || len(sealed) != 1 {
			t.Fatalf("values: %s: seal: %v", c.ID, err)
		}
		stored, present := sealed[0][corpus.Values.Field]
		if present == (c.Input.Type == "null" && c.Null == "sql") {
			t.Fatalf("values: %s: stored=%v for a %q null", c.ID, present, c.Null)
		}
		if present {
			out.Values[c.ID] = exchangeStoredOf(stored)
		} else {
			out.Values[c.ID] = exchangeStored{Terms: map[string]string{}}
		}
	}

	plan := exchangeRecordPlan(corpus)
	for _, row := range corpus.Record.Rows {
		source := record.Source{}
		stored := exchangeStoredRecord{Passthrough: map[string]conformanceInput{}, Fields: map[string]exchangeStored{}}
		for _, f := range corpus.Record.Fields {
			input := row.Values[f.Name]
			if f.Passthrough {
				// The host keeps it; it is typed here so a text the kind
				// cannot carry is a corpus error.
				if v := conformanceValue(t, input); v == nil || input.Type != f.Kind {
					t.Fatalf("record: %s: %s: a passthrough carries a typed value", row.ID, f.Name)
				}
				stored.Passthrough[f.Name] = input
				continue
			}
			source[f.Name] = conformanceValue(t, input)
		}
		sealed, err := cipher.Seal(ctx, plan, []record.Source{source})
		if err != nil || len(sealed) != 1 {
			t.Fatalf("record: %s: seal: %v", row.ID, err)
		}
		for _, f := range plan.Fields {
			outputs, present := sealed[0][f.Name]
			if !present {
				if row.Values[f.Name].Type != "null" || f.Null != record.SQLNull {
					t.Fatalf("record: %s: %s: only a SQL null stores nothing", row.ID, f.Name)
				}
				continue
			}
			stored.Fields[f.Name] = exchangeStoredOf(outputs)
		}
		out.Record[row.ID] = stored
	}

	blobPlan := exchangeBlobPlan(corpus)
	for _, c := range corpus.Blob.Cases {
		encoded, err := vcffi.MarshalStorage(c.Value)
		if err != nil {
			t.Fatalf("blob: %s: %v", c.ID, err)
		}
		sealed, err := cipher.Seal(ctx, blobPlan, []record.Source{{corpus.Blob.Field: encoded}})
		if err != nil || len(sealed) != 1 {
			t.Fatalf("blob: %s: seal: %v", c.ID, err)
		}
		out.Blobs[c.ID] = hex.EncodeToString(sealed[0][corpus.Blob.Field].Ciphertext)
	}
	return out
}

func exchangeIDs[T any](m map[string]T) map[string]bool {
	ids := make(map[string]bool, len(m))
	for id := range m {
		ids[id] = true
	}
	return ids
}

func consumeExchange(t *testing.T, ctx context.Context, cipher *encrypt.Cipher, corpus *exchangeCorpus, values []valueCase, artifacts exchangeArtifacts, origin string) {
	t.Helper()
	if artifacts.Version != 1 || artifacts.Profile != exchangeProfile {
		t.Fatalf("%s: artifact version %d profile %q", origin, artifacts.Version, artifacts.Profile)
	}
	p := artifacts.Producer
	switch p.Language {
	case "rust", "go", "python", "typescript":
	default:
		t.Fatalf("%s: unknown producer language %q", origin, p.Language)
	}
	if origin != "self" && p.Language == "go" {
		t.Fatalf("%s: another runner's artifacts", origin)
	}
	if p.SDK == "" || p.SDKVersion == "" {
		t.Fatalf("%s: the producer names its SDK and version", origin)
	}
	if p.Backend != "native" && p.Backend != "wasi" {
		t.Fatalf("%s: unknown backend %q", origin, p.Backend)
	}
	if p.Engine.Name != "stack-encrypt" || (p.Engine.Version == nil && p.Engine.GuestSHA256 == nil) {
		t.Fatalf("%s: the engine is identified by name and version or guest hash", origin)
	}
	if p.KeySource.Kind != "deterministic" || p.KeySource.Seed != corpus.Seed {
		t.Fatalf("%s: the artifacts were not written under the shared deterministic seed", origin)
	}
	claimed := map[string]bool{}
	for _, profile := range p.Profiles {
		claimed[profile] = true
	}
	if !claimed[exchangeProfile] || !claimed[corpus.Values.Profile] {
		t.Fatalf("%s: the artifacts claim both profiles", origin)
	}
	if !reflect.DeepEqual(p.Capabilities, corpus.RequiredCapabilities) {
		t.Fatalf("%s: capabilities %v", origin, p.Capabilities)
	}

	positive := exchangePositiveCases(values)
	if len(positive) == 0 || len(corpus.Record.Rows) == 0 || len(corpus.Blob.Cases) == 0 {
		t.Fatal("an empty corpus")
	}
	want := map[string]bool{}
	for _, c := range positive {
		want[c.ID] = true
	}
	if !reflect.DeepEqual(exchangeIDs(artifacts.Values), want) {
		t.Fatalf("%s: the value artifacts are not exactly the corpus's cases", origin)
	}
	want = map[string]bool{}
	for _, row := range corpus.Record.Rows {
		want[row.ID] = true
	}
	if !reflect.DeepEqual(exchangeIDs(artifacts.Record), want) {
		t.Fatalf("%s: the record artifacts are not exactly the corpus's rows", origin)
	}
	want = map[string]bool{}
	for _, c := range corpus.Blob.Cases {
		want[c.ID] = true
	}
	if !reflect.DeepEqual(exchangeIDs(artifacts.Blobs), want) {
		t.Fatalf("%s: the blob artifacts are not exactly the corpus's cases", origin)
	}

	for _, c := range positive {
		what := origin + ": values: " + c.ID
		plan := exchangeValuePlan(corpus, c)
		stored := artifacts.Values[c.ID]
		input := conformanceValue(t, c.Input)
		omitted := c.Input.Type == "null" && c.Null == "sql"
		if (stored.C == nil) != omitted {
			t.Fatalf("%s: storage", what)
		}
		sealed := record.Sealed{}
		if omitted {
			if len(stored.Terms) != 0 {
				t.Fatalf("%s: a SQL null stores no term", what)
			}
		} else {
			checkExchangeTerms(t, ctx, cipher, plan, corpus.Values.Field, stored, c.Outputs, c.Unanswered, input, c.EqualQuery, what)
			sealed[corpus.Values.Field] = exchangeOutputsOf(t, stored, what)
		}
		opened, err := cipher.Open(ctx, plan, []record.Sealed{sealed})
		if err != nil || len(opened) != 1 || len(opened[0]) != 1 {
			t.Fatalf("%s: open: %v", what, err)
		}
		if !sameValue(opened[0][corpus.Values.Field], input) {
			t.Fatalf("%s: opened %#v, want %#v", what, opened[0][corpus.Values.Field], input)
		}
	}

	plan := exchangeRecordPlan(corpus)
	for _, row := range corpus.Record.Rows {
		what := origin + ": record: " + row.ID
		stored := artifacts.Record[row.ID]
		sealed := record.Sealed{}
		passthroughs := 0
		for _, f := range corpus.Record.Fields {
			input := row.Values[f.Name]
			if f.Passthrough {
				passthroughs++
				carried, ok := stored.Passthrough[f.Name]
				if !ok || carried != input {
					t.Fatalf("%s: %s: passthrough %+v, want %+v", what, f.Name, carried, input)
				}
				continue
			}
			outputs, present := stored.Fields[f.Name]
			if !present {
				if input.Type != "null" || f.Null != "sql" {
					t.Fatalf("%s: %s: only a SQL null is absent", what, f.Name)
				}
				continue
			}
			checkExchangeTerms(t, ctx, cipher, plan, f.Name, outputs, f.Outputs, nil, conformanceValue(t, input), nil, what+": "+f.Name)
			sealed[f.Name] = exchangeOutputsOf(t, outputs, what+": "+f.Name)
		}
		if len(stored.Passthrough) != passthroughs {
			t.Fatalf("%s: %d passthrough fields, want %d", what, len(stored.Passthrough), passthroughs)
		}
		opened, err := cipher.Open(ctx, plan, []record.Sealed{sealed})
		if err != nil || len(opened) != 1 || len(opened[0]) != len(plan.Fields) {
			t.Fatalf("%s: open: %v", what, err)
		}
		for _, f := range plan.Fields {
			want := conformanceValue(t, row.Values[f.Name])
			if got, ok := opened[0][f.Name]; !ok || !sameValue(got, want) {
				t.Fatalf("%s: %s: opened %#v, want %#v", what, f.Name, got, want)
			}
		}
	}

	blobPlan := exchangeBlobPlan(corpus)
	for _, c := range corpus.Blob.Cases {
		what := origin + ": blob: " + c.ID
		sealed := record.Sealed{corpus.Blob.Field: {Ciphertext: unhexT(t, artifacts.Blobs[c.ID])}}
		opened, err := cipher.Open(ctx, blobPlan, []record.Sealed{sealed})
		if err != nil || len(opened) != 1 {
			t.Fatalf("%s: open: %v", what, err)
		}
		encoded, ok := opened[0][corpus.Blob.Field].([]byte)
		if !ok {
			t.Fatalf("%s: opened as %T, not bytes", what, opened[0][corpus.Blob.Field])
		}
		var got exchangeBlobValue
		if err := gensupport.Opaque(gensupport.Values{gensupport.OpaqueField: encoded}, &got); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !sameBlob(got, c.Value) {
			t.Fatalf("%s: opened %+v, want %+v", what, got, c.Value)
		}
	}
}

// TestArtifactExchange writes fresh artifacts of every kind this runner
// exchanges and opens them, then opens the artifacts STACK_EXCHANGE_INPUT
// names, written by another runner. STACK_EXCHANGE_OUTPUT receives this
// runner's artifacts for the other runner. Nothing frozen is read or
// written; a missing guest fails in required mode.
func TestArtifactExchange(t *testing.T) {
	root := filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1")
	var corpus exchangeCorpus
	readConformanceJSON(t, filepath.Join(root, "exchange.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != exchangeProfile || corpus.Values.Corpus != "values.json" {
		t.Fatal("unsupported exchange corpus")
	}
	if corpus.EQL.Table != "profiles" || corpus.EQL.Schema != "eql_v4" {
		t.Fatal("unsupported EQL lane")
	}
	if _, err := os.Stat(filepath.Join("..", "..", "..", corpus.EQL.Fixture)); err != nil {
		t.Fatalf("the EQL lane's fixture: %v", err)
	}
	var values struct {
		Version              int                  `json:"version"`
		Profile              string               `json:"profile"`
		RequiredCapabilities []string             `json:"required_capabilities"`
		Cases                []valueCase          `json:"cases"`
		HostConversions      []hostConversionCase `json:"host_conversions"`
	}
	readConformanceJSON(t, filepath.Join(root, corpus.Values.Corpus), &values)
	if values.Version != 1 || values.Profile != corpus.Values.Profile || len(values.Cases) == 0 {
		t.Fatal("unsupported value corpus")
	}
	names := map[string]bool{}
	passthrough := false
	for _, f := range corpus.Record.Fields {
		if names[f.Name] {
			t.Fatalf("repeated record field %q", f.Name)
		}
		names[f.Name] = true
		passthrough = passthrough || f.Passthrough
	}
	if !passthrough {
		t.Fatal("the record has a passthrough field")
	}
	for _, row := range corpus.Record.Rows {
		if len(row.Values) != len(names) {
			t.Fatalf("%s: every field has a value", row.ID)
		}
		for name := range row.Values {
			if !names[name] {
				t.Fatalf("%s: unknown field %q", row.ID, name)
			}
		}
	}
	seed, err := hex.DecodeString(corpus.Seed)
	if err != nil || len(seed) != 32 {
		t.Fatal("expected a 32-byte deterministic test seed")
	}
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte(seed))
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cipher := client.DefaultKeyset()

	fresh := produceExchange(t, ctx, cipher, &corpus, values.Cases)
	consumeExchange(t, ctx, cipher, &corpus, values.Cases, fresh, "self")

	if path := os.Getenv("STACK_EXCHANGE_OUTPUT"); path != "" {
		data, err := json.MarshalIndent(fresh, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if path := os.Getenv("STACK_EXCHANGE_INPUT"); path != "" {
		var foreign exchangeArtifacts
		readConformanceJSON(t, path, &foreign)
		origin := foreign.Producer.Language + " artifacts"
		t.Logf("exchange: opening %s from %s %s over %s (%s)", origin, foreign.Producer.SDK, foreign.Producer.SDKVersion, foreign.Producer.Backend, path)
		consumeExchange(t, ctx, cipher, &corpus, values.Cases, foreign, origin)
	}
}
