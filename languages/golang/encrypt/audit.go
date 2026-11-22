package encrypt

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// AuditMetadata is facts about a call that ZeroKMS writes to its audit log.
//
// Every Encrypt and Decrypt asks ZeroKMS for data keys. ZeroKMS logs each
// request with the identity that made it. AuditMetadata provides additional
// context for that log. Typical facts are the purpose of the call, a request
// ID, a trace ID, and the end user that the call acts for.
//
// Build it with [NewAuditMetadata] and one method for each fact. Then attach
// it to a cipher with [Cipher.Audit], or to a client with [Client.Audit]:
//
//	metadata := encrypt.NewAuditMetadata().
//		Text("purpose", "list issues").
//		Text("request_id", requestID)
//	people, err := users.Decrypt(ctx, cipher.Audit(metadata), rows)
//
// Audit metadata is optional. A cipher without it sends none. It is the
// Rust crate's AuditMetadata, and the unverified context of the ZeroKMS
// protocol.
//
// # Rules
//
//   - ZeroKMS does not verify the facts. The program states them, and
//     ZeroKMS records them as given. No key depends on them, so do not use
//     them for access control.
//   - A decrypt does not need them. A Decrypt can send different facts from
//     the Encrypt, or none.
//   - Do not send plaintext or secrets. ZeroKMS writes the facts to its
//     logs. Do not send anything derived from plaintext either.
//   - An IP address or a user agent is personal data. The SDK sends only
//     what you pass, and adds nothing.
//   - A query sends none. A query term is derived from the index key of
//     the keyset, so a query asks ZeroKMS for no data key. A query through
//     a cipher that has metadata still works. But refused metadata fails
//     every call through the cipher, a query included.
//   - A call that asks for no data key sends none. An Encrypt or a Decrypt
//     of no rows is one such call.
//
// # Values
//
// Each method adds one fact, and its parameter type is the type of the
// value. So the compiler refuses a value of another type:
//
//   - [AuditMetadata.Text] takes a string;
//   - [AuditMetadata.Bool] takes a bool;
//   - [AuditMetadata.Int] takes an int, and [AuditMetadata.Int64] an int64;
//   - [AuditMetadata.Float] takes a float64;
//   - [AuditMetadata.Time] takes a time.Time;
//   - [AuditMetadata.Null] takes no value;
//   - [AuditMetadata.TextList] and [AuditMetadata.List] take a list;
//   - [AuditMetadata.Map] takes a nested AuditMetadata.
//
// Convert a value of another type yourself. For a named type such as
// `type ID string`, write string(id). For a []byte, send text, such as its
// hex form. ZeroKMS reads an integer as an int64, so there is no method for
// a uint64: convert it, or send it as text.
//
// ZeroKMS records each value as you give it, with two exceptions:
//
//   - A time is sent as RFC 3339 text in UTC, such as
//     "2026-11-20T10:00:00Z", because ZeroKMS has no type for a time. The
//     text keeps the instant to the nanosecond. It does not keep the zone
//     that the time was in.
//   - A float that is not finite is sent as null.
//
// The compiler cannot check three things, because they depend on the
// value. The first call through the cipher refuses each one with
// [ErrEncoding]:
//
//   - a key or a text that is not valid UTF-8;
//   - a time outside the years 0 to 9999, because RFC 3339 has no form for
//     it;
//   - maps and lists nested more than 32 levels deep.
//
// # Copies
//
// An AuditMetadata is a value. Each method returns a new one, and leaves
// the one it was called on unchanged. So a program can build a base once,
// and add to it for each request. The zero value has no facts, as
// [NewAuditMetadata] gives.
//
// A fact replaces one that has the same key, and takes nothing from it. So
// a refused value that is replaced is not reported.
type AuditMetadata struct {
	// facts is every fact, by key; nil is none. It is a function for the
	// reason [auditFacts] gives.
	facts func() map[string]auditFact
	// added counts the facts set so far, so that [AuditMetadata.refused]
	// can report the first refusal.
	added int
}

// auditFact is one fact of [AuditMetadata], with what the checks need to
// know of it. A fact that replaces another takes nothing from it.
type auditFact struct {
	// value is the fact as the cipher sends it.
	value any
	// depth is how many levels of maps and lists the value nests: 0 for a
	// value that is neither.
	depth int
	// refused is why the fact cannot be sent, naming its key, or nil.
	refused error
	// order is when the fact was set, among the facts of its metadata.
	order int
}

// NewAuditMetadata is metadata with no facts. A cipher given it sends
// none.
func NewAuditMetadata() AuditMetadata { return AuditMetadata{} }

// auditFacts is facts in the form the cipher sends: the caller cannot reach
// or change them. nil is no facts.
//
// It is a function that returns the facts, and not the map itself, so that
// printing a cipher or an [AuditMetadata] never shows a fact. Package fmt
// prints a function as an address, under every verb. It prints a map, or a
// pointer to a struct, with its contents under some verbs. A fact can be
// personal data. A debug log is not the audit log.
type auditFacts func() map[string]any

// with is these facts and added's together. A fact in added replaces one
// that has the same key. The result shares no map with either.
func (a auditFacts) with(added auditFacts) auditFacts {
	if added == nil {
		return a
	}
	if a == nil {
		return added
	}
	facts := make(map[string]any, len(a())+len(added()))
	for key, value := range a() {
		facts[key] = value
	}
	for key, value := range added() {
		facts[key] = value
	}
	return func() map[string]any { return facts }
}

// maxAuditDepth is how deep maps and lists in audit metadata can nest. The
// transport codec allows 128 levels for a whole call. The limit here is
// well inside that. So the refusal of deeper metadata comes from this
// package, as an [ErrEncoding] that names Audit.
const maxAuditDepth = 32

// errAuditDepth is the refusal of metadata nested deeper than
// [maxAuditDepth].
var errAuditDepth = fmt.Errorf("the metadata nests more than %d levels deep", maxAuditDepth)

// errNotUTF8 is the refusal of a text that is not valid UTF-8. It does not
// show the text.
var errNotUTF8 = errors.New("text that is not valid UTF-8")

// set is this metadata with the fact key set to value. The value nests
// depth levels below it. refused is why the value cannot be sent, or nil.
//
// A refusal names the key of its fact and never a value: a key is a name
// the program chose, and a value can be personal data. A key that is not
// valid UTF-8 is refused without being shown.
func (m AuditMetadata) set(key string, value any, depth int, refused error) AuditMetadata {
	switch {
	case !utf8.ValidString(key):
		refused = errors.New("a key is not valid UTF-8")
	case refused != nil:
		refused = fmt.Errorf("the fact %q: %w", key, refused)
	}
	facts := make(map[string]auditFact, m.len()+1)
	if m.facts != nil {
		for k, fact := range m.facts() {
			facts[k] = fact
		}
	}
	facts[key] = auditFact{value: value, depth: depth, refused: refused, order: m.added}
	return AuditMetadata{facts: func() map[string]auditFact { return facts }, added: m.added + 1}
}

// len is the number of facts.
func (m AuditMetadata) len() int {
	if m.facts == nil {
		return 0
	}
	return len(m.facts())
}

// depth is how many levels of maps and lists the facts nest, the map that
// holds them included: 0 for no facts.
func (m AuditMetadata) depth() int {
	depth := 0
	if m.facts != nil {
		for _, fact := range m.facts() {
			depth = max(depth, fact.depth+1)
		}
	}
	return depth
}

// refused is why the facts cannot be sent, or nil: the refusal of the first
// fact set that has one, then a nesting deeper than [maxAuditDepth].
func (m AuditMetadata) refused() error {
	var first *auditFact
	if m.facts != nil {
		for _, fact := range m.facts() {
			if fact.refused != nil && (first == nil || fact.order < first.order) {
				first = &fact
			}
		}
	}
	switch {
	case first != nil:
		return first.refused
	case m.depth() > maxAuditDepth:
		return errAuditDepth
	}
	return nil
}

// Text adds the fact key with a text value. A fact already under that key
// is replaced. Text that is not valid UTF-8 is reported by the first call
// through the cipher, as [ErrEncoding].
func (m AuditMetadata) Text(key, value string) AuditMetadata {
	text, err := auditText(value)
	return m.set(key, text, 0, err)
}

// Bool adds the fact key with a bool value. A fact already under that key
// is replaced.
func (m AuditMetadata) Bool(key string, value bool) AuditMetadata {
	return m.set(key, value, 0, nil)
}

// Int adds the fact key with an integer value. A fact already under that
// key is replaced. For an int64, use [AuditMetadata.Int64].
func (m AuditMetadata) Int(key string, value int) AuditMetadata {
	return m.set(key, int64(value), 0, nil)
}

// Int64 adds the fact key with an integer value. A fact already under that
// key is replaced. ZeroKMS reads an integer as an int64, so an int64 is the
// widest integer a fact can have.
func (m AuditMetadata) Int64(key string, value int64) AuditMetadata {
	return m.set(key, value, 0, nil)
}

// Float adds the fact key with a float value. A fact already under that key
// is replaced. A float that is not finite is sent as null.
func (m AuditMetadata) Float(key string, value float64) AuditMetadata {
	return m.set(key, value, 0, nil)
}

// Time adds the fact key with a time. A fact already under that key is
// replaced. The time is sent as RFC 3339 text in UTC: see [AuditMetadata].
// A time outside the years 0 to 9999 is reported by the first call through
// the cipher, as [ErrEncoding].
func (m AuditMetadata) Time(key string, value time.Time) AuditMetadata {
	text, err := auditTime(value)
	return m.set(key, text, 0, err)
}

// Null adds the fact key with no value, sent as null. A fact already under
// that key is replaced.
func (m AuditMetadata) Null(key string) AuditMetadata {
	return m.set(key, nil, 0, nil)
}

// TextList adds the fact key with a list of text values. A fact already
// under that key is replaced. For a list of other values, build an
// [AuditList] and use [AuditMetadata.List].
func (m AuditMetadata) TextList(key string, values ...string) AuditMetadata {
	return m.List(key, NewAuditList().Text(values...))
}

// List adds the fact key with a list of values. A fact already under that
// key is replaced.
func (m AuditMetadata) List(key string, values AuditList) AuditMetadata {
	return m.set(key, values.sent(), max(values.depth, 1), values.err)
}

// Map adds the fact key with a nested map of facts. A fact already under
// that key is replaced.
func (m AuditMetadata) Map(key string, nested AuditMetadata) AuditMetadata {
	return m.set(key, nested.sent(), max(nested.depth(), 1), nested.refused())
}

// sent is the facts as one value of an outer map or list: a map, empty for
// no facts.
func (m AuditMetadata) sent() map[string]any {
	facts := make(map[string]any, m.len())
	if m.facts != nil {
		for key, fact := range m.facts() {
			facts[key] = fact.value
		}
	}
	return facts
}

// String shows the keys of the facts, quoted and in order, and never a
// value. A value can be personal data. A debug log is not the audit log.
func (m AuditMetadata) String() string {
	keys := make([]string, 0, m.len())
	for key := range m.sent() {
		keys = append(keys, strconv.Quote(key))
	}
	sort.Strings(keys)
	return "AuditMetadata{keys: [" + strings.Join(keys, " ") + "]}"
}

// AuditList is a list of values for one fact of [AuditMetadata]: see
// [AuditMetadata.List]. Each method appends values and returns a new list.
// The zero value is an empty list, as [NewAuditList] gives.
//
//	hosts := encrypt.NewAuditList().Text("db-1", "db-2")
//	metadata := encrypt.NewAuditMetadata().List("hosts", hosts)
type AuditList struct {
	// items is the values, in order; nil is none. It is a function for the
	// reason [auditFacts] gives.
	items func() []any
	// depth is how many levels of maps and lists the values nest.
	depth int
	// err is the first value that was refused, as for [AuditMetadata].
	err error
}

// NewAuditList is an empty list.
func NewAuditList() AuditList { return AuditList{} }

// add is this list with values appended. The values nest depth levels, and
// refused is why one of them cannot be sent, or nil.
func (l AuditList) add(depth int, refused error, values ...any) AuditList {
	next := AuditList{depth: max(l.depth, depth+1), err: l.err}
	items := make([]any, 0, len(l.sent())+len(values))
	items = append(append(items, l.sent()...), values...)
	next.items = func() []any { return items }
	if next.err == nil {
		next.err = refused
	}
	return next
}

// sent is the values as the cipher sends them: a list, empty for none.
func (l AuditList) sent() []any {
	if l.items == nil {
		return []any{}
	}
	return l.items()
}

// Text appends text values. Text that is not valid UTF-8 is reported by the
// first call through the cipher, as [ErrEncoding].
func (l AuditList) Text(values ...string) AuditList {
	var refused error
	items := make([]any, len(values))
	for i, value := range values {
		text, err := auditText(value)
		if err != nil && refused == nil {
			refused = err
		}
		items[i] = text
	}
	return l.add(0, refused, items...)
}

// Bool appends bool values.
func (l AuditList) Bool(values ...bool) AuditList {
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	return l.add(0, nil, items...)
}

// Int appends integer values.
func (l AuditList) Int(values ...int) AuditList {
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = int64(value)
	}
	return l.add(0, nil, items...)
}

// Int64 appends integer values.
func (l AuditList) Int64(values ...int64) AuditList {
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	return l.add(0, nil, items...)
}

// Float appends float values. A float that is not finite is sent as null.
func (l AuditList) Float(values ...float64) AuditList {
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	return l.add(0, nil, items...)
}

// Time appends times, each sent as RFC 3339 text in UTC. A time outside
// the years 0 to 9999 is reported by the first call through the cipher, as
// [ErrEncoding].
func (l AuditList) Time(values ...time.Time) AuditList {
	var refused error
	items := make([]any, len(values))
	for i, value := range values {
		text, err := auditTime(value)
		if err != nil && refused == nil {
			refused = err
		}
		items[i] = text
	}
	return l.add(0, refused, items...)
}

// Null appends one null.
func (l AuditList) Null() AuditList {
	return l.add(0, nil, nil)
}

// List appends one nested list.
func (l AuditList) List(nested AuditList) AuditList {
	return l.add(max(nested.depth, 1), nested.err, nested.sent())
}

// Map appends one nested map of facts.
func (l AuditList) Map(nested AuditMetadata) AuditList {
	return l.add(max(nested.depth(), 1), nested.refused(), nested.sent())
}

// auditText is value as the cipher sends it, or the refusal of text that
// is not valid UTF-8. The codec refuses such text too, but at the call, and
// without naming Audit.
func auditText(value string) (any, error) {
	if !utf8.ValidString(value) {
		return nil, errNotUTF8
	}
	return value, nil
}

// auditTime is value as the cipher sends it: RFC 3339 text in UTC. ZeroKMS
// has no type for a time, and the guest's contract gives every language SDK
// this one text form.
func auditTime(value time.Time) (any, error) {
	utc := value.UTC()
	if year := utc.Year(); year < 0 || year > 9999 {
		return nil, errors.New("a time outside the years 0 to 9999 has no RFC 3339 form")
	}
	return utc.Format(time.RFC3339Nano), nil
}

// checked is the facts of metadata, or an [ErrEncoding] that names Audit
// for a value that metadata refused.
func (m AuditMetadata) checked() (auditFacts, error) {
	if err := m.refused(); err != nil {
		return nil, fmt.Errorf("%w: Audit: %v", ErrEncoding, err)
	}
	if m.facts == nil {
		return nil, nil
	}
	facts := m.sent()
	return func() map[string]any { return facts }, nil
}

// Audit returns a cipher that sends metadata to ZeroKMS with every data-key
// request it makes, for the ZeroKMS audit log. Every Encrypt and Decrypt
// through the cipher sends it, and so does every read of an encrypted JSON
// document. A query sends none. See [AuditMetadata] for what ZeroKMS does
// with the facts, and for what you must not send.
//
// Audit adds to the facts the cipher already has. A fact in metadata
// replaces one that has the same key:
//
//	service := cipher.Audit(encrypt.NewAuditMetadata().Text("service", "billing"))
//	request := service.Audit(encrypt.NewAuditMetadata().Text("request_id", requestID))
//
// The second cipher sends both facts. The first still sends one.
//
// A value that the metadata refused is reported by the first call through
// the cipher, as [ErrEncoding]. [AuditMetadata] lists those values.
func (cph *Cipher) Audit(metadata AuditMetadata) *Cipher {
	next := cph.copy()
	facts, err := metadata.checked()
	if err != nil {
		if next.err == nil {
			next.err = err
		}
		return next
	}
	next.audit = cph.audit.with(facts)
	return next
}

// Audit returns a [Decrypter] that opens records as the client does, under
// whichever keyset sealed each one. It sends metadata to ZeroKMS with every
// data-key request it makes. See [AuditMetadata] for what ZeroKMS does with
// the facts, and for what you must not send.
//
//	metadata := encrypt.NewAuditMetadata().Text("purpose", "export")
//	people, err := users.Decrypt(ctx, client.Audit(metadata), rows)
//
// A value that the metadata refused is reported by the first Decrypt
// through the Decrypter, as [ErrEncoding].
func (c *Client) Audit(metadata AuditMetadata) Decrypter {
	facts, err := metadata.checked()
	return &auditedClient{client: c, audit: facts, err: err}
}

// auditedClient is a client with audit metadata: what [Client.Audit]
// returns.
type auditedClient struct {
	client *Client
	audit  auditFacts
	// err is a refused metadata value, reported by the first Open: no call
	// on this package panics.
	err error
}

// Open decrypts records as [Client.Open] does, and sends the metadata with
// every data-key request. For generated code.
func (a *auditedClient) Open(ctx context.Context, plan *record.Plan, records []record.Sealed) ([]record.Source, error) {
	if a == nil || a.client == nil {
		return nil, fmt.Errorf("%w: Open on a nil *Client", ErrEncoding)
	}
	if a.err != nil {
		return nil, a.err
	}
	return a.client.openAny(ctx, a.audit, plan, records)
}
