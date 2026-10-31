package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Entity -name Entity

// Entity holds its custom field values as an encrypted JSON document (the
// EQL type JsonSearch). Each emergency contact's relationship, call count
// and age order, so the generated EntityFields.CustomFieldValues has
// Elements.ExtraEmergencyContacts, whose Match tests them on one contact
// together. A contact's name is not ordered.
type Entity struct {
	_                 struct{}          `stash:"context=entities"`
	ID                int64             `stash:"id,passthrough"`
	CustomFieldValues CustomFieldValues `stash:"custom_field_values,encrypt_into=JsonSearch(ordered=$.extra.emergency_contacts[*].relationship;$.extra.emergency_contacts[*].previous_call_count;$.extra.emergency_contacts[*].age)"`
}

// CustomFieldValues is an entity's custom field values document.
type CustomFieldValues struct {
	Extra CustomFieldExtra `json:"extra"`
}

// CustomFieldExtra holds an entity's emergency contacts.
type CustomFieldExtra struct {
	EmergencyContacts []EmergencyContact `json:"emergency_contacts"`
}

// EmergencyContact is one emergency contact of an entity.
type EmergencyContact struct {
	Name              string `json:"name"`
	Relationship      string `json:"relationship"`
	PreviousCallCount int64  `json:"previous_call_count"`
	Age               int64  `json:"age"`
}
