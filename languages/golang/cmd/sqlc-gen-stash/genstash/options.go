package genstash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

// Options are the options of a codegen entry of the plugin.
type Options struct {
	// Go are sqlc-gen-go's options for the package, as in sqlc's own gen.go
	// block, without out: the codegen entry's out is the package's folder.
	Go json.RawMessage `json:"go"`
	// Stash holds the plugin's own options.
	Stash StashOptions `json:"stash"`
}

// StashOptions are the plugin's own options.
type StashOptions struct {
	// EmitTableFields writes a <Model>Fields value for every table, whatever
	// omit_unused_structs says.
	EmitTableFields bool `json:"emit_table_fields"`
	// Identity derives a column's encryption identity from its name, the
	// way a regex find and replace does. A column it doesn't match is
	// refused.
	Identity *Identity `json:"identity"`
	// EmitMethodsWithParamEncryption adds query methods accepting plaintext
	// parameters. Defaults to false.
	EmitMethodsWithParamEncryption bool `json:"emit_methods_with_param_encryption"`
	// EmitMethodsWithResultDecryption adds query methods returning plaintext
	// results. Defaults to false.
	EmitMethodsWithResultDecryption bool `json:"emit_methods_with_result_decryption"`
}

// Identity derives an encryption identity from a column name: the matched
// part of the name is replaced with Replacement, in which $1 or ${name}
// stands for a capture group of Pattern, as in
// regexp.Regexp.ReplaceAllString.
type Identity struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
}

// GlobalOptions are the top-level options.<plugin name>.
type GlobalOptions struct {
	// Go are sqlc-gen-go's global options, its overrides and renames for
	// every codegen entry, as sqlc's own top-level overrides.go.
	Go json.RawMessage `json:"go"`
}

// parseOptions reads a codegen entry's options. It refuses an unknown key,
// an identity whose pattern or replacement is missing, and a pattern that
// doesn't compile.
func parseOptions(raw []byte) (Options, error) {
	var o Options
	if err := decodeStrict(raw, &o); err != nil {
		return o, &Error{Option: "options", Err: fmt.Errorf("%w: %w", ErrInvalidOption, err)}
	}
	if id := o.Stash.Identity; id != nil {
		if id.Pattern == "" || id.Replacement == "" {
			return o, &Error{Option: "options.stash.identity", Err: ErrIncompleteIdentity}
		}
		if _, err := regexp.Compile(id.Pattern); err != nil {
			return o, &Error{Option: "options.stash.identity.pattern", Err: fmt.Errorf("%w: %w", ErrInvalidOption, err)}
		}
	}

	return o, nil
}

// parseGlobalOptions reads the top-level options.<plugin name>, which may be
// empty, from option, its path in sqlc.yaml. It refuses an unknown key.
func parseGlobalOptions(raw []byte, option string) (GlobalOptions, error) {
	var g GlobalOptions
	if err := decodeStrict(raw, &g); err != nil {
		return g, &Error{Option: option, Err: fmt.Errorf("%w: %w", ErrInvalidOption, err)}
	}

	return g, nil
}

// decodeStrict decodes raw, which may be empty, into v, refusing a key v
// has no field for.
func decodeStrict(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	return dec.Decode(v)
}
