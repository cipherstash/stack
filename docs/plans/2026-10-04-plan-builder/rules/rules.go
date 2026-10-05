// Package rules decides what to encrypt from the data categories that the
// protobuf schema gives each field. Only the generate program runs it.
package rules

import (
	"example.com/app/internal/pb"
	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
)

//go:generate go run ../cmd/genencrypt

// The key is the full name of the field option in proto/classification.proto.
var category = policy.Key("classification.data_categories")

// Base applies to every message. The first rule that matches a field decides it.
var Base = policy.FirstOf(
	policy.When(category.Under("user.government_id"), policy.EncryptInto("TextEq")),
	policy.When(category.Under("user.contact.email"), policy.EncryptIndex(encrypt.Equality, encrypt.Match())),
	policy.When(category.Under("user"), policy.Encrypt()),
)

// Individuals adds the rules for one message. A field with no data category
// needs a rule too: with none, the generator stops.
var Individuals = policy.ForMessage(&pb.Individual{}, policy.Context("individuals"),
	policy.FirstOf(
		policy.When(policy.Field("medicare_no"), policy.EncryptInto("TextEq"), policy.Name("medicare_number")),
		policy.When(policy.Field("id"), policy.Passthrough()),
		policy.When(policy.Field("nickname"), policy.Passthrough()),
	).OrElse(Base),
)
