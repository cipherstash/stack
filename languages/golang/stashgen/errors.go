package stashgen

import "fmt"

// FieldError is a mistake in one field's declaration. Every refusal names the
// type and the field, and never a value.
type FieldError struct {
	// Type is the Go type the field belongs to: "User" or "crm.Contact".
	Type string
	// Field is the Go name of the field, or "" for a mistake about the type.
	Field string
	// Reason says what is wrong, without the type and field.
	Reason string
}

func (e *FieldError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("stashgen: %s: %s", e.Type, e.Reason)
	}
	return fmt.Sprintf("stashgen: %s.%s: %s", e.Type, e.Field, e.Reason)
}

func fieldErr(typeName, field, format string, args ...any) error {
	return &FieldError{Type: typeName, Field: field, Reason: fmt.Sprintf(format, args...)}
}
