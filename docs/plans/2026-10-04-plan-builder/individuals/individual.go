// Package individuals must build without individual_stash.go, because the
// generate program imports it. Code that uses the generated names lives in
// individualstore.
package individuals

//go:generate go run -tags stashgen ../cmd/genplans

type Individual struct {
	ID         int64
	Name       string
	Email      string
	MedicareNo string
	Nickname   string
}
