// Package testclient is where package encrypt hands package encrypttest the
// one constructor it needs: a client over a given guest build, initialised
// with a seed in place of a client key. The constructor reaches encrypt's
// unexported instance and client, and encrypttest imports encrypt, so encrypt
// registers it here on init. Nothing outside the encrypt tree can import this
// package, so the constructor is in no public API.
package testclient

import (
	"context"
	"errors"
)

// Constructor builds a client over a deterministic-kms build of the guest,
// with every key derived from seed. plain and withEQL load the test builds
// without and with the EQL types; the constructor calls the one a
// production client in this program would match. It returns the
// *encrypt.Client as any, because this package cannot import encrypt to
// name the type.
type Constructor func(ctx context.Context, plain, withEQL func() ([]byte, error), seed [32]byte) (any, error)

var constructor Constructor

// Register installs encrypt's constructor. Called once, by encrypt's init.
func Register(c Constructor) { constructor = c }

// errNotRegistered is a program that reached New without package encrypt
// initialised, which the import graph rules out.
var errNotRegistered = errors.New("encrypt: test client constructor not registered")

// New calls the registered constructor.
func New(ctx context.Context, plain, withEQL func() ([]byte, error), seed [32]byte) (any, error) {
	if constructor == nil {
		return nil, errNotRegistered
	}
	return constructor(ctx, plain, withEQL, seed)
}
