package encrypt

// Verification of #1773, not for merge as is: the hook the external chaos
// test builds a client against a fake ZeroKMS with.

// VerifyTestCredentials is the test client id and key, with a static token.
func VerifyTestCredentials() Credentials { return testCredentials(staticToken("stub-token")) }
