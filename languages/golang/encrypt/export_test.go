package encrypt

import (
	"context"
	"reflect"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// The test-only ways to give a client a token. The public API takes tokens
// only from auth strategies; the tests that talk to httptest stubs
// need a fixed one, and get it here rather than through anything a caller
// could reach.

// tokenFunc adapts a function to a tokenSource.
type tokenFunc func(ctx context.Context) (string, error)

func (f tokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// staticToken is a tokenSource that always returns token.
func staticToken(token string) tokenSource {
	return tokenFunc(func(context.Context) (string, error) { return token, nil })
}

// newTestCredentials is NewCredentials with token in place of a strategy:
// the same type, so the same consume-on-refusal and no-Close semantics.
// A nil token is refused as NewCredentials refuses a nil strategy.
func newTestCredentials(clientID string, key *ClientKey, token tokenSource) Credentials {
	return &explicitCredentials{clientID: clientID, key: key, token: token}
}

// withZeroKMSURL points the client at a ZeroKMS stub. There is no public
// option for it: applications take the endpoint from the token, or from
// CS_ZEROKMS_HOST.
func withZeroKMSURL(url string) ClientOption {
	return func(o *clientOptions) { o.zerokmsURL = url }
}

// GuestPlanInput is the encoded plan object a record call over t sends the
// guest under p, each context extended by ext: what the external tests
// compare byte for byte. Test-only; not part of the package's API.
func GuestPlanInput(p Plan, t reflect.Type, ext ...any) ([]byte, error) {
	o := applyOptions([]RecordOption{WithPlan(p), ExtendContext(ext...)})
	bound, err := planFor(t, o)
	if err != nil {
		return nil, err
	}
	obj, err := planValue(bound, o)
	if err != nil {
		return nil, err
	}
	return vcffi.Marshal(obj)
}
