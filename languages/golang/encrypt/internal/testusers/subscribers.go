package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Subscriber -name Subscriber

// Subscriber holds encrypted JSON documents (the EQL type JsonSearch) of Go
// types: encoding/json writes each to JSON text when it is sealed and reads
// it back when it is opened. Its profile orders $.age and each visit's $.at,
// its preferences are SQL NULL when nil, and its labels are a map.
type Subscriber struct {
	_       struct{}          `stash:"context=subscribers"`
	ID      int64             `stash:"id,passthrough"`
	Profile SubscriberProfile `stash:"profile,encrypt_into=JsonSearch(ordered=$.age;$.visits[*].at)"`
	Prefs   *SubscriberPrefs  `stash:"prefs,encrypt_into=JsonSearch,null=sql"`
	Labels  map[string]string `stash:"labels,encrypt_into=JsonSearch"`
}

// SubscriberProfile is a subscriber's profile document. Big, Small and Score hold
// the values a float64 would round: they cross as their exact digits.
type SubscriberProfile struct {
	Name   string  `json:"name"`
	Age    int64   `json:"age"`
	Tier   string  `json:"tier,omitempty"`
	Big    uint64  `json:"big"`
	Small  int64   `json:"small"`
	Score  float64 `json:"score"`
	Visits []Visit `json:"visits"`
}

// Visit is one visit in a profile.
type Visit struct {
	At    int64  `json:"at"`
	Place string `json:"place"`
}

// SubscriberPrefs is a subscriber's optional preferences document.
type SubscriberPrefs struct {
	Theme string `json:"theme"`
}

// ProfileNeedle is a containment needle for a subscriber's profile: every
// field is a pointer with omitempty, so a field left nil is not in the
// needle and does not narrow the query.
type ProfileNeedle struct {
	Name   *string `json:"name,omitempty"`
	Age    *int64  `json:"age,omitempty"`
	Tier   *string `json:"tier,omitempty"`
	Visits []Visit `json:"visits,omitempty"`
}
