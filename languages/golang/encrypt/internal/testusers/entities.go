package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Entity -name Entity

// Entity holds its custom field values as an encrypted JSON document (the
// EQL type JsonSearch). Its weight orders, and so does each emergency
// contact's relationship, call count and age, so the generated
// EntityFields.CustomFieldValues has At.Weight and
// Elements.ExtraEmergencyContacts, whose Match tests a contact's members
// together. A contact's name is not ordered.
type Entity struct {
	_                 struct{}          `stash:"context=entities"`
	ID                int64             `stash:"id,passthrough"`
	CustomFieldValues CustomFieldValues `stash:"custom_field_values,encrypt_into=JsonSearch(ordered=$.weight;$.extra.emergency_contacts[*].relationship;$.extra.emergency_contacts[*].previous_call_count;$.extra.emergency_contacts[*].age)"`
}

// CustomFieldValues is an entity's custom field values document. Every
// member but Extra is left out of the document when it is nil, so a
// document holds only the values an entity has.
type CustomFieldValues struct {
	Score   *float64         `json:"score,omitempty"`
	Weight  *float64         `json:"weight,omitempty"`
	Address *CustomAddress   `json:"address,omitempty"`
	Extra   CustomFieldExtra `json:"extra"`
}

// CustomAddress is an entity's address. A nil Postcode is JSON null.
type CustomAddress struct {
	Postcode *string `json:"postcode"`
}

// CustomFieldExtra holds an entity's country, preferred languages and
// emergency contacts.
type CustomFieldExtra struct {
	Country            string             `json:"country,omitempty"`
	PreferredLanguages []string           `json:"preferred_languages,omitempty"`
	EmergencyContacts  []EmergencyContact `json:"emergency_contacts"`
}

// EmergencyContact is one emergency contact of an entity.
type EmergencyContact struct {
	Name              string `json:"name"`
	Relationship      string `json:"relationship"`
	PreviousCallCount int64  `json:"previous_call_count"`
	Age               int64  `json:"age"`
}
