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

// WholeFloatUpTo is wholeFloatUpTo, for the external tests: the bound a
// float offset is read to, at a limit of the test's choosing.
func WholeFloatUpTo(f float64, limit int64) (int64, bool) {
	return wholeFloatUpTo(f, limit)
}
