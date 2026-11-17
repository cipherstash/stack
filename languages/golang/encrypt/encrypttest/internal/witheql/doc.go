// Package witheql tests encrypttest.NewClient in a program that links
// package eql, as an application whose generated code names an EQL type
// does. NewClient must then pick the test build with the EQL types. Whether
// eql is linked is fixed for a whole test binary, so these tests have a
// package of their own, and encrypttest's own tests keep a binary without
// eql. It holds no code.
package witheql
