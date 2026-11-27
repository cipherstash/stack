// Package testclient is where package encrypt hands package encrypttest the
// two constructors it needs: a client over a given guest build, initialised
// with a seed in place of a client key, and a checker over a given guest
// build. The constructors reach encrypt's unexported instance and client,
// and encrypttest imports encrypt, so encrypt registers them here on
// init. Nothing outside the encrypt tree can import this package, so the
// constructors are in no public API.
package testclient

import (
	"context"
	"errors"
)

// Builds loads the two deterministic-kms builds of the guest: Plain
// without the EQL types, and WithEQL with them. A constructor calls the
// one a production client in this program would match.
type Builds struct {
	Plain, WithEQL func() ([]byte, error)
}

// Constructor builds a client over a deterministic-kms build of the guest,
// the one of builds a production client in this program would match, with
// every key derived from seed. It returns the *encrypt.Client as any,
// because this package cannot import encrypt to name the type.
type Constructor func(ctx context.Context, builds Builds, seed [32]byte) (any, error)

var constructor Constructor

// CheckerConstructor builds a checker over a test build of the guest,
// the one a production client in this program would match, as Constructor
// picks it. It returns the *encrypt.Checker as any.
type CheckerConstructor func(ctx context.Context, builds Builds) (any, error)

var checkerConstructor CheckerConstructor

// Register installs encrypt's constructors. Called once, by encrypt's init.
func Register(client Constructor, checker CheckerConstructor) {
	constructor = client
	checkerConstructor = checker
}

// errNotRegistered is a program that reached New without package encrypt
// initialised, which the import graph rules out.
var errNotRegistered = errors.New("encrypt: test client constructor not registered")

// New calls the registered constructor.
func New(ctx context.Context, builds Builds, seed [32]byte) (any, error) {
	if constructor == nil {
		return nil, errNotRegistered
	}
	return constructor(ctx, builds, seed)
}

// NewChecker calls the registered checker constructor.
func NewChecker(ctx context.Context, builds Builds) (any, error) {
	if checkerConstructor == nil {
		return nil, errNotRegistered
	}
	return checkerConstructor(ctx, builds)
}
