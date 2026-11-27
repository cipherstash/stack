package encrypt_test

import (
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

// A user who sees a missing-guest error needs a tagged version of the
// module, not a build task, so the message says that before it names the
// task a contributor runs in a checkout. The prefix stays as it was, because
// a caller may match it (#1923 quotes the EQL one in the stashgen README).
func TestGuestNotBuiltMessagesLeadWithATaggedVersion(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		prefix string
		task   string
	}{
		{"without the EQL types", encrypt.ErrGuestNotBuilt, "encrypt: guest module not built", "mise run wasm:guest:build`"},
		{"with the EQL types", encrypt.ErrEQLGuestNotBuilt, "encrypt: guest module with the EQL types not built", "mise run wasm:guest:build:eql`"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if !strings.HasPrefix(msg, tt.prefix) {
				t.Fatalf("message %q does not start with %q", msg, tt.prefix)
			}
			tagged := strings.Index(msg, "tagged version")
			task := strings.Index(msg, tt.task)
			if tagged < 0 || task < 0 || tagged > task {
				t.Fatalf("message %q must name a tagged version before %q", msg, tt.task)
			}
		})
	}
}
