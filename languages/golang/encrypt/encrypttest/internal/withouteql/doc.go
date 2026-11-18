// Package withouteql tests encrypttest in a program that does not link
// package eql, so encrypttest must pick the test build without the EQL types,
// as encrypt.NewClient picks the production build without them. Whether eql
// is linked is fixed for a whole test binary, so this needs a package of its
// own. It holds no code.
package withouteql
