package auth_test

import (
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// A user who sees a missing-guest error needs a tagged version of the
// module, not a build task, so the message says that before it names the
// task a contributor runs in a checkout.
func TestGuestNotBuiltMessageLeadsWithATaggedVersion(t *testing.T) {
	msg := auth.ErrGuestNotBuilt.Error()
	if !strings.HasPrefix(msg, "auth: guest module not built") {
		t.Fatalf("message %q lost its prefix", msg)
	}
	tagged := strings.Index(msg, "tagged version")
	task := strings.Index(msg, "mise run wasm:auth-guest:build`")
	if tagged < 0 || task < 0 || tagged > task {
		t.Fatalf("message %q must name a tagged version before the build task", msg)
	}
}
