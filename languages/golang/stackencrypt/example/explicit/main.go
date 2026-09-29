// Command explicit connects the stack-encrypt Go binding to real ZeroKMS
// with credentials the application supplies itself: the client key and the
// access key come from a secrets source, the client id and workspace from
// configuration, and nothing is read from CS_* variables or the developer
// profile. It is the NewCredentials counterpart of ../example, which uses
// AutoCredentials.
//
//	mise run wasm:guest:build wasm:auth-guest:build   # both embedded guests
//	go run ./stackencrypt/example/explicit \
//	    -secrets-dir /run/secrets \
//	    -client-id 6a70bd18-99ac-4650-b104-37eec3a15b09 \
//	    -workspace-crn crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY
//
// The secrets directory holds two files, client-key and access-key, the way
// a Kubernetes or Docker secret is mounted. See README.md.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cipherstash/cipherstash-suite/bindings/go/stackauth"
	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
)

type user struct {
	ID    int64  `stash:"-"`
	Email string `stash:"context=users/email,index=eq"`
}

type config struct {
	secretsDir          string
	clientID            string
	workspaceCRN        string
	ctsHost             string
	requireLockedMemory bool
}

func main() {
	var cfg config
	flag.StringVar(&cfg.secretsDir, "secrets-dir", "/run/secrets", "directory holding the client-key and access-key secrets")
	flag.StringVar(&cfg.clientID, "client-id", "", "the ZeroKMS client id (not a secret)")
	flag.StringVar(&cfg.workspaceCRN, "workspace-crn", "", "the workspace the access key belongs to")
	flag.StringVar(&cfg.ctsHost, "cts-host", "", "pin the authentication endpoint (default: from the workspace CRN)")
	flag.BoolVar(&cfg.requireLockedMemory, "require-locked-memory", false, "refuse to run on memory that cannot be locked in RAM")
	flag.Parse()
	if cfg.clientID == "" || cfg.workspaceCRN == "" {
		fmt.Fprintln(os.Stderr, "usage: explicit -client-id ID -workspace-crn CRN [-secrets-dir DIR]")
		os.Exit(2)
	}
	if err := run(context.Background(), cfg, fileSecrets{dir: cfg.secretsDir}); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}
}

// secrets is where the application keeps what must not be in its
// configuration. This example reads mounted files; an application would
// call its secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager)
// here instead. The bytes returned are the caller's to wipe or hand on.
type secrets interface {
	Get(ctx context.Context, name string) ([]byte, error)
}

type fileSecrets struct{ dir string }

func (s fileSecrets) Get(_ context.Context, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return nil, fmt.Errorf("reading secret %q: %w", name, err)
	}
	// A mounted secret often ends in a newline. Trimming returns a
	// sub-slice of the same array, so nothing is copied.
	return bytes.TrimSpace(b), nil
}

func run(ctx context.Context, cfg config, secrets secrets) error {
	// The credential guest the token strategy runs in. The caller opens
	// it, so the caller chooses its memory policy: under
	// -require-locked-memory it is locked from the start and stays locked
	// as it grows. NewClient checks it either way, below.
	var storeOpts []stackauth.Option
	if cfg.requireLockedMemory {
		storeOpts = append(storeOpts, stackauth.RequireLockedMemory())
	}
	// No profile: this application's credentials are all explicit.
	store, err := stackauth.OpenWithoutProfile(ctx, storeOpts...)
	if err != nil {
		return fmt.Errorf("opening the credential guest: %w", err)
	}
	// Deferred calls run last-first: the client closes before the strategy
	// it asks for tokens, and the strategy before the store it lives in.
	defer store.Close()

	accessKey, err := secrets.Get(ctx, "access-key")
	if err != nil {
		return err
	}
	var strategyOpts []stackauth.StrategyOption
	if cfg.ctsHost != "" {
		strategyOpts = append(strategyOpts, stackauth.WithAuthBaseURL(cfg.ctsHost))
	}
	// The access key crosses as a string, which Go cannot wipe; the bytes
	// it was read into can be.
	strategy, err := store.AccessKey(ctx, cfg.workspaceCRN, string(accessKey), strategyOpts...)
	clear(accessKey)
	if err != nil {
		return fmt.Errorf("access-key strategy: %w", err)
	}
	defer strategy.Close()

	keyMaterial, err := secrets.Get(ctx, "client-key")
	if err != nil {
		return err
	}
	// NewClientKey takes ownership of the bytes; NewClient wipes them.
	creds := stackencrypt.NewCredentials(cfg.clientID, stackencrypt.NewClientKey(keyMaterial), strategy)

	opts := []stackencrypt.ClientOption{stackencrypt.WithCredentials(creds)}
	if cfg.requireLockedMemory {
		opts = append(opts, stackencrypt.WithRequireLockedMemory())
	}
	client, err := stackencrypt.NewClient(ctx, opts...)
	if err != nil {
		return fmt.Errorf("connecting to ZeroKMS: %w", err)
	}
	defer client.Close()
	// The memory state covers both guests: the crypto guest holding the
	// key, and the credential guest the token strategy runs in.
	fmt.Printf("connected (%v)\n", client)

	// A key is for one client. These credentials are spent, and a second
	// client needs a new key; nothing was sent to find that out.
	if _, err := stackencrypt.NewClient(ctx, stackencrypt.WithCredentials(creds)); errors.Is(err, stackencrypt.ErrCredentialsConsumed) {
		fmt.Println("reusing the credentials is refused: the key was consumed by the first client")
	} else {
		return fmt.Errorf("reusing the credentials: got %v, want ErrCredentialsConsumed", err)
	}

	cipher := client.DefaultKeyset()
	rows := []user{{ID: 1, Email: "alice@example.com"}, {ID: 2, Email: "bob@example.com"}}
	records, err := cipher.EncryptRecords(ctx, rows)
	if err != nil {
		return fmt.Errorf("encrypting records: %w", err)
	}
	probe, err := cipher.Term(ctx, "bob@example.com", stackencrypt.MustContext("users/email"), stackencrypt.Equality)
	if err != nil {
		return fmt.Errorf("deriving a probe: %w", err)
	}
	for i, r := range records {
		if probe.(stackencrypt.EqualityTerm).Equal(r["Email"].Equality) {
			fmt.Printf("sealed %d rows; the probe for bob@example.com matches row %d\n", len(records), i)
		}
	}
	var back []user
	if err := cipher.DecryptRecords(ctx, records, &back); err != nil {
		return fmt.Errorf("decrypting records: %w", err)
	}
	fmt.Printf("opened %v\n", back)
	return nil
}
