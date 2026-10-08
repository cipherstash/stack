package guest

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// Diagnose is diagnose, for the external tests: it fetches a failure's
// detail under a context of the test's choosing, with no export failing
// first.
func (e Exports) Diagnose(ctx context.Context, m api.Module, kind error) error {
	return e.diagnose(ctx, m, kind)
}
