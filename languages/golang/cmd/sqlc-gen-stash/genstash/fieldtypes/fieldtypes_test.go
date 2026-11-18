package fieldtypes

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
)

// TestEncryptedHaveNoZero checks that no encrypted field type has a Zero
// method, through anything it embeds either: a query builder that infers a
// plaintext column's Go type from Zero would accept the column, and compare
// and sort its ciphertext as if it were plaintext.
func TestEncryptedHaveNoZero(t *testing.T) {
	if _, ok := reflect.TypeFor[Column[string]]().MethodByName("Zero"); !ok {
		t.Fatal("Column has no Zero method, so this test can't find one")
	}
	// The values are built as the generated <Model>Fields build them.
	var d gensupport.Declaration
	for _, v := range []any{
		newField[Stored[string, eql.Text]](d, "t", "c", "Text", ""),
		newField[Eq[string, eql.TextEq, eql.TextEqQuery]](d, "t", "c", "TextEq", ""),
		newField[Ord[string, eql.TextOrd, eql.TextOrdQuery]](d, "t", "c", "TextOrd", ""),
		newField[Match[string, eql.TextMatch, eql.TextMatchQuery]](d, "t", "c", "TextMatch", ""),
		newField[EqOrd[string, eql.TextOrd, eql.TextOrdQuery]](d, "t", "c", "TextOrd", ""),
		newField[Search[string, eql.TextSearch, eql.TextSearchQuery]](d, "t", "c", "TextSearch", ""),
		newField[Document[json.RawMessage, eql.JSONSearch, eql.JSONSearchQuery, eql.JSONEntry, eql.JSONSearchPredicateQuery]](d, "t", "c", "JsonSearch", ""),
	} {
		typ := reflect.TypeOf(v)
		for _, typ := range []reflect.Type{typ, reflect.PointerTo(typ)} {
			if _, ok := typ.MethodByName("Zero"); ok {
				t.Errorf("%s has a Zero method", typ)
			}
		}
	}
}
