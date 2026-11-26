package encrypt

import (
	"errors"
	"fmt"
)

// codeRetrieveKeyFailed is the code of a data-key request that ZeroKMS
// failed. With ErrForbidden, ZeroKMS refused the data key.
const codeRetrieveKeyFailed = "stack_kms::retrieve_key_failed"

// ZeroKMS refuses a data key with HTTP 403 for two causes, and its answer
// does not say which: the value is opened under another context than it was
// sealed under, or the client has no grant for the value's keyset. The guest
// gives a Help that names both. The call knows more, so these say which one
// it was where they can.
//
// A Help never names a scope's or a binding's value, or a context label:
// those are context values, which a Diagnostic never carries. It names how
// many parts there are, and the keyset, whose name or id it may carry.

// explainRefusal gives err the Help for a data key ZeroKMS refused on a
// call through this cipher. The cipher loaded its keyset before it asked for
// a key, so the client has access to the keyset, and the context is what
// differs. Any other error is returned as it is.
func (cph *Cipher) explainRefusal(err error) error {
	return withRefusalHelp(err, fmt.Sprintf(
		"ZeroKMS refused the data key, because the value was sealed under another context than this cipher opens it under. "+
			"The client loaded this cipher's keyset (%s), so it has access to that keyset. "+
			"This cipher adds %s and %s to the context. "+
			"Open the value through a cipher with the same Cipher.Scope and Cipher.Bind parts as the cipher that encrypted it. "+
			"A row whose context field was changed after it was written fails the same way.",
		describeKeyset(cph.keyset), countParts(len(cph.extension), "scope"), countParts(len(cph.bindings), "binding")))
}

// clientRefusalHelp is the Help for a data key ZeroKMS refused on a call
// through the Client, which opens each value under the keyset that sealed
// it without loading that keyset first.
const clientRefusalHelp = "ZeroKMS refused the data key. The Client opens a value only under the context stored with it, so one of these is the cause: " +
	"the value was encrypted through a cipher with Cipher.Scope or Cipher.Bind parts, which only a cipher with the same parts opens; " +
	"this client has no grant for the keyset the value was sealed under; " +
	"or the row's context field was changed after it was written. " +
	"Open a scoped or bound value through a cipher like the one that encrypted it, and check the keyset's grants in ZeroKMS."

// explainClientRefusal gives err the Help for a data key ZeroKMS refused on
// a call through the Client. Any other error is returned as it is.
func explainClientRefusal(err error) error {
	return withRefusalHelp(err, clientRefusalHelp)
}

// withRefusalHelp sets help on the Diagnostic of err when err is a data key
// ZeroKMS refused, and returns err. The Diagnostic is the one the guest made
// for this call, so no other caller holds it.
func withRefusalHelp(err error, help string) error {
	if !errors.Is(err, ErrForbidden) {
		return err
	}
	var d *Diagnostic
	if errors.As(err, &d) && d.Code == codeRetrieveKeyFailed {
		d.Help = help
	}
	return err
}

// describeKeyset names the keyset a selector selects, as a Help says it.
// Keyset names and ids are details a Diagnostic may carry.
func describeKeyset(sel KeysetSelector) string {
	switch s := sel.(type) {
	case KeysetName:
		return fmt.Sprintf("keyset %q", string(s))
	case KeysetID:
		return "keyset " + s.String()
	case defaultKeyset:
		return "the client's default keyset"
	default:
		return "its keyset"
	}
}

// countParts says how many parts of a kind there are: "no scope parts",
// "1 scope part", "2 scope parts".
func countParts(n int, kind string) string {
	switch n {
	case 0:
		return "no " + kind + " parts"
	case 1:
		return "1 " + kind + " part"
	default:
		return fmt.Sprintf("%d %s parts", n, kind)
	}
}
