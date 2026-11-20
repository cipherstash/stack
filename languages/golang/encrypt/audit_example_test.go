package encrypt_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The examples here are the snippets of the README's "Audit metadata"
// section. Each one needs a ZeroKMS client, so it has no Output comment:
// `go test` compiles it and does not run it.
//
// The example program in encrypt/example runs a decrypt with audit metadata.

// A program states its service once, and adds a request ID for each
// request. Every Decrypt through the request's cipher sends both facts.
func ExampleCipher_Audit() {
	ctx := context.Background()
	client, err := encrypt.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	var rows []testusers.EncryptedUser // read from the database
	requestID := "req_01J9Z3"

	service := client.DefaultKeyset().Audit(encrypt.AuditMetadata{"service": "billing"})
	request := service.Audit(encrypt.AuditMetadata{
		"purpose":    "list issues",
		"request_id": requestID,
		"at":         time.Now(),
	})
	people, err := testusers.Decrypt(ctx, request, rows)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(people))
}

// To decrypt rows from any keyset, with metadata, pass client.Audit(..)
// where a Decrypter is taken.
func ExampleClient_Audit() {
	ctx := context.Background()
	client, err := encrypt.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	var rows []testusers.EncryptedUser // read from the database

	people, err := testusers.Decrypt(ctx, client.Audit(encrypt.AuditMetadata{"purpose": "export"}), rows)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(people))
}
