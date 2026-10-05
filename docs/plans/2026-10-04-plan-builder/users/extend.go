package users

import (
	"context"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

// RoundTripForTenant shows a context extension. The parts extend every field's
// context, so the write, the query and the read must pass the same parts.
// With other parts, decryption fails and the equality term matches nothing.
func RoundTripForTenant(ctx context.Context, cipher *stackencrypt.Cipher, part string, user User) (User, error) {
	extend := stackencrypt.ExtendContext(part)

	record, err := usersPlan.Encrypt(ctx, cipher, user, extend)
	if err != nil {
		return User{}, err
	}
	if _, err := emailPlan.Equality(ctx, cipher, user.Email, extend); err != nil {
		return User{}, err
	}
	return usersPlan.Decrypt(ctx, cipher, record, extend)
}
