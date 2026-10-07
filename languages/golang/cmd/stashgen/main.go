// Command stashgen writes the encrypted type and its functions for a struct
// with stash tags. go generate runs it from the struct's package:
//
//	//go:generate go tool stashgen -type User
//
// See README.md beside this file for the steps and the flag reference.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	// The build of the engine that holds the EQL types: the generator
	// asks the embedded guest which EQL types it produces, so it links the
	// build that has them. Generated code imports encrypt/eql only when it
	// names one.
	_ "github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/stashgen"
)

func main() {
	os.Exit(run(os.Args[1:], "", os.Stdout, os.Stderr, stashgen.GuestEngine))
}

// modelFlags collects the -model flags, which repeat.
type modelFlags []stashgen.ModelRequest

func (m *modelFlags) String() string {
	parts := make([]string, len(*m))
	for i, r := range *m {
		parts[i] = r.Name + "=" + r.Type
		if r.Declares != "" {
			parts[i] += ":" + r.Declares
		}
	}
	return strings.Join(parts, " ")
}

func (m *modelFlags) Set(s string) error {
	r, err := stashgen.ParseModelFlag(s)
	if err != nil {
		return err
	}
	*m = append(*m, r)
	return nil
}

// run is main without the process: dir is the package directory ("" for the
// working directory, which is where go generate runs), and newEngine gives
// the engine that checks the declaration.
func run(args []string, dir string, stdout, stderr io.Writer, newEngine func(context.Context) (stashgen.Engine, error)) int {
	fs := flag.NewFlagSet("stashgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	req := stashgen.Request{Dir: dir}
	var models modelFlags
	fs.StringVar(&req.Type, "type", "", "the struct that carries the stash tags (required)")
	fs.StringVar(&req.Name, "name", "", "write EncryptN, DecryptN and NFields instead of Encrypt, Decrypt and Fields")
	fs.StringVar(&req.For, "for", "", "P.F: -type declares the tags for F, a type in package P")
	fs.Var(&models, "model", "Name=R or Name=R:D: a model R for separate columns; writes EncryptName and DecryptName (repeatable)")
	fs.BoolVar(&req.Redact, "redact", false, "write String, GoString and LogValue methods on the -type struct")
	fs.StringVar(&req.Output, "output", "", "the file to write (default: the type's name in lower case, with _stash.go)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: stashgen -type T [-name N] [-for P.F] [-model Name=R[:D]]... [-redact] [-output file]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "stashgen: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}
	if req.Type == "" {
		fmt.Fprintln(stderr, "stashgen: -type is required")
		fs.Usage()
		return 2
	}
	req.Models = models

	ctx := context.Background()
	engine, err := newEngine(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	file, err := stashgen.FromTags(ctx, engine, req)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	for _, n := range file.Notices {
		fmt.Fprintln(stderr, n)
	}
	if err := file.Write(); err != nil {
		fmt.Fprintf(stderr, "stashgen: write %s: %v\n", file.Path, err)
		return 1
	}
	return 0
}
