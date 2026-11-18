// Package example is sqlc-gen-stash's output for a small schema, regenerated
// by go generate and checked by CI like the rest of the generated code. It
// shows what the plugin writes for a table model, a partial projection, an
// outer join, a self join, a batch query, an UPDATE's and a search's
// parameters, and the per-column values of every table, including contacts,
// which no query returns, but not of the view user_summaries: the package
// db, which it writes as sqlc-gen-go does, and its own package db/dbstash.
package example

//go:generate go build -o .bin/sqlc-gen-stash ../..
//go:generate sqlc generate
