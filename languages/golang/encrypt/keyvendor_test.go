package encrypt_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Hermetic tests of a client with a key vendor backend (CIP-5311): the
// deterministic-kms test build stands in for ZeroKMS, the backend is the
// static key or AWS KMS behind a fake RoundTripper, and its credentials
// cross the real vendor_credential_get import.

// The key vendor and key mode bytes of the keyset record (CIP-5306).
const (
	recordAWS    = 1
	recordStatic = 5
	modeWrapped  = 1
	modeDerived  = 2
)

// frame is stack-kms-vendor's framing: the piece count, then each piece's
// length and bytes, all lengths u64 little-endian. Written again here, so a
// record this test builds is a second implementation's check of the format.
func frame(pieces ...[]byte) []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(pieces)))
	for _, p := range pieces {
		out = binary.LittleEndian.AppendUint64(out, uint64(len(p)))
		out = append(out, p...)
	}
	return out
}

// recordKeyAAD is the associated data a keyset record's key is wrapped
// under.
func recordKeyAAD(id [16]byte, vendor, mode byte) []byte {
	purpose := "root-key"
	if mode == modeWrapped {
		purpose = "index-key"
	}
	return frame([]byte("stack-kms-vendor/keyset-record-key/v1"), []byte(purpose), id[:], []byte{vendor}, []byte{mode})
}

// keysetRecord renders a keyset record's text form.
func keysetRecord(id [16]byte, vendor, mode byte, name, keyRef string, wrapped []byte) string {
	b := []byte{1, vendor, mode}
	b = append(b, id[:]...)
	b = append(b, byte(len(name)))
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(keyRef)))
	b = append(b, keyRef...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(wrapped)))
	b = append(b, wrapped...)
	return "stack-keyset:" + base64.RawURLEncoding.EncodeToString(b)
}

// staticWrap wraps key as the static key backend does: version 1, a 12-byte
// nonce, then AES-256-GCM under staticKey with aad.
func staticWrap(t *testing.T, staticKey, key, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(staticKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{1}, nonce...), gcm.Seal(nil, nonce, key, aad)...)
}

func randomID(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

// vendorClient is a deterministic client with v, or a skip when the test
// build is absent.
func vendorClient(t *testing.T, rt http.RoundTripper, v encrypt.KeyVendor, records ...string) *encrypt.Client {
	t.Helper()
	c, err := encrypt.NewDeterministicVendorClient(context.Background(), testSeed, rt, v, records...)
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// roundTrip seals people under cipher and opens them through cipher and the
// client, and returns what was sealed.
func roundTrip(t *testing.T, c *encrypt.Client, cipher *encrypt.Cipher) []testusers.EncryptedUser {
	t.Helper()
	ctx := context.Background()
	encrypted, err := testusers.Encrypt(ctx, cipher, people)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]testusers.User(nil), people...)
	want[0].Internal = ""
	for _, d := range []encrypt.Decrypter{cipher, c} {
		back, err := testusers.Decrypt(ctx, d, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, want) {
			t.Fatalf("round trip: got %+v", back)
		}
	}
	return encrypted
}

func TestStaticKeyVendorRoundTrip(t *testing.T) {
	staticKey := bytes.Repeat([]byte{0x42}, 32)
	rootKey := bytes.Repeat([]byte{0x07}, 32)
	id := randomID(t)
	record := keysetRecord(id, recordStatic, modeDerived, "local", "dev-key", staticWrap(t, staticKey, rootKey, recordKeyAAD(id, recordStatic, modeDerived)))

	key := append([]byte(nil), staticKey...)
	c := vendorClient(t, refusing{}, encrypt.StaticKey{KeyRef: "dev-key", Key: key}, record)
	if !bytes.Equal(key, make([]byte, 32)) {
		t.Error("the static key was not wiped")
	}
	ctx := context.Background()

	vendor := c.Keyset(encrypt.KeysetName("local"))
	got, err := vendor.KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != encrypt.KeysetID(id) {
		t.Fatalf("keyset id %s, want %s", got, encrypt.KeysetID(id))
	}
	sealed := roundTrip(t, c, vendor)
	// A vendor keyset seals v2 leaves; the router keeps the default keyset
	// on the ZeroKMS stand-in, which seals v1.
	if v := sealed[0].Email.Ciphertext[0]; v != 2 {
		t.Errorf("a vendor leaf has format version %d, want 2", v)
	}
	zerokms := roundTrip(t, c, c.DefaultKeyset())
	if v := zerokms[0].Email.Ciphertext[0]; v != 1 {
		t.Errorf("a ZeroKMS leaf has format version %d, want 1", v)
	}

	// A keyset-bound cipher refuses the other backend's rows before any key
	// is asked for.
	if _, err := testusers.Decrypt(ctx, c.DefaultKeyset(), sealed); !errors.Is(err, encrypt.ErrForeignKeyset) {
		t.Errorf("default keyset opening a vendor row: %v, want ErrForeignKeyset", err)
	}

	// Equal plaintexts give equal terms under the vendor keyset too, and
	// they differ from the ZeroKMS keyset's.
	if !sealed[1].Age.Equality.Equal(sealed[2].Age.Equality) || sealed[1].Age.Equality.Equal(zerokms[1].Age.Equality) {
		t.Error("vendor equality terms do not follow the plaintext and the keyset")
	}

	// The same record under another static key does not open.
	other := vendorClient(t, refusing{}, encrypt.StaticKey{KeyRef: "dev-key", Key: bytes.Repeat([]byte{0x43}, 32)}, record)
	if _, err := testusers.Encrypt(ctx, other.Keyset(encrypt.KeysetName("local")), people); !errors.Is(err, encrypt.ErrAuthentication) {
		t.Errorf("a wrong static key: %v, want ErrAuthentication", err)
	}
}

// refusing is a RoundTripper for a backend that must make no request.
type refusing struct{}

func (refusing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("this test makes no HTTP request")
}

// fakeKMS answers the AWS KMS JSON API for the three operations the client
// uses. A "ciphertext blob" is the key and the SHA-256 of the encryption
// context's cipherstash:aad, so a decrypt under another context fails as
// AWS KMS fails it. It checks that every request is SigV4-signed with the
// host's credentials.
type fakeKMS struct {
	mu       sync.Mutex
	calls    map[string]int
	refuse   bool
	failures []string
}

func (f *fakeKMS) fail(format string, args ...any) {
	f.failures = append(f.failures, fmt.Sprintf(format, args...))
}

func (f *fakeKMS) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	op := strings.TrimPrefix(req.Header.Get("X-Amz-Target"), "TrentService.")
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[op]++
	if req.URL.String() != "https://kms.ap-southeast-2.amazonaws.com/" {
		f.fail("URL %s", req.URL)
	}
	if auth := req.Header.Get("Authorization"); !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || !strings.Contains(auth, "/ap-southeast-2/kms/aws4_request") {
		f.fail("authorization %q", auth)
	}
	if token := req.Header.Get("X-Amz-Security-Token"); token != "fixture-session-token" {
		f.fail("session token %q", token)
	}
	if f.refuse {
		return response(400, `{"__type":"AccessDeniedException","message":"not allowed"}`), nil
	}
	var in struct {
		KeyID             string            `json:"KeyId"`
		CiphertextBlob    []byte            `json:"CiphertextBlob"`
		EncryptionContext map[string]string `json:"EncryptionContext"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		f.fail("body: %v", err)
		return response(400, `{"__type":"ValidationException","message":"bad body"}`), nil
	}
	if in.KeyID != awsKeyARN {
		f.fail("key %q", in.KeyID)
	}
	bound := sha256.Sum256([]byte(in.EncryptionContext["cipherstash:aad"]))
	switch op {
	case "GenerateDataKey":
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		blob := append(append([]byte(nil), key...), bound[:]...)
		return response(200, fmt.Sprintf(`{"KeyId":%q,"Plaintext":%q,"CiphertextBlob":%q}`, awsKeyARN, base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(blob))), nil
	case "Decrypt":
		if len(in.CiphertextBlob) != 64 || !bytes.Equal(in.CiphertextBlob[32:], bound[:]) {
			return response(400, `{"__type":"InvalidCiphertextException","message":""}`), nil
		}
		return response(200, fmt.Sprintf(`{"KeyId":%q,"Plaintext":%q}`, awsKeyARN, base64.StdEncoding.EncodeToString(in.CiphertextBlob[:32]))), nil
	}
	f.fail("operation %q", op)
	return response(400, `{"__type":"UnsupportedOperationException","message":""}`), nil
}

func (f *fakeKMS) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": {"application/x-amz-json-1.1"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

const awsKeyARN = "arn:aws:kms:ap-southeast-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// awsRecord is a keyset record whose key the fake KMS unwraps: the key and
// the digest of the encryption context the client sends for it.
func awsRecord(t *testing.T, mode byte, name string) string {
	t.Helper()
	id := randomID(t)
	aad := base64.RawURLEncoding.EncodeToString(recordKeyAAD(id, recordAWS, mode))
	bound := sha256.Sum256([]byte(aad))
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return keysetRecord(id, recordAWS, mode, name, awsKeyARN, append(key, bound[:]...))
}

// countingCredentials is the host's credential source: fixed temporary
// credentials, counted.
type countingCredentials struct {
	mu    sync.Mutex
	asked int
	err   error
}

func (c *countingCredentials) AWSCredentials(context.Context) (encrypt.AWSCredentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked++
	if c.err != nil {
		return encrypt.AWSCredentials{}, c.err
	}
	return encrypt.AWSCredentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "fixture-secret-access-key",
		SessionToken:    "fixture-session-token",
		Expires:         time.Now().Add(time.Hour),
	}, nil
}

func TestAWSKMSVendorThroughTheHostTransport(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		mode byte
		// The vendor calls one Encrypt of len(people) rows makes, by
		// operation.
		sealCalls map[string]int
	}{
		// Derived data keys: one unwrap of the root key, cached for its TTL.
		{"derived", modeDerived, map[string]int{"Decrypt": 1}},
		// Wrapped data keys: the index key once per settle, and one
		// GenerateDataKey per sealed field of every row (3 per row).
		{"wrapped", modeWrapped, map[string]int{"Decrypt": 1, "GenerateDataKey": 3 * len(people)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kms := &fakeKMS{}
			creds := &countingCredentials{}
			c := vendorClient(t, kms, encrypt.AWSKMS{Region: "ap-southeast-2", Credentials: creds}, awsRecord(t, tc.mode, "payments"))
			cipher := c.Keyset(encrypt.KeysetName("payments"))
			if _, err := testusers.Encrypt(ctx, cipher, people); err != nil {
				t.Fatal(err)
			}
			for op, want := range tc.sealCalls {
				if got := kms.count(op); got != want {
					t.Errorf("%s calls: %d, want %d", op, got, want)
				}
			}
			roundTrip(t, c, cipher)
			if len(kms.failures) > 0 {
				t.Fatalf("the fake KMS saw: %s", strings.Join(kms.failures, "; "))
			}
			calls := 0
			for _, n := range kms.calls {
				calls += n
			}
			if creds.asked != calls {
				t.Errorf("the credential source was asked %d times for %d requests", creds.asked, calls)
			}
		})
	}
}

func TestAWSKMSVendorFailures(t *testing.T) {
	ctx := context.Background()

	// AWS KMS refuses: ErrForbidden, with the vendor in the diagnostic.
	kms := &fakeKMS{refuse: true}
	c := vendorClient(t, kms, encrypt.AWSKMS{Region: "ap-southeast-2", Credentials: &countingCredentials{}}, awsRecord(t, modeDerived, "payments"))
	_, err := testusers.Encrypt(ctx, c.Keyset(encrypt.KeysetName("payments")), people)
	if !errors.Is(err, encrypt.ErrForbidden) {
		t.Fatalf("refused: %v, want ErrForbidden", err)
	}
	d := encrypt.WantDiagnostic(t, err, "stack_kms::backend")
	if d.Fields["vendor"] != "aws-kms" {
		t.Errorf("vendor field %v", d.Fields["vendor"])
	}

	// The host's credential source fails: the guest reports a transport
	// failure, and the source's own error is attached for errors.Is. No
	// request is sent.
	errSource := errors.New("fixture credential source is down")
	kms = &fakeKMS{}
	c = vendorClient(t, kms, encrypt.AWSKMS{Region: "ap-southeast-2", Credentials: &countingCredentials{err: errSource}}, awsRecord(t, modeDerived, "payments"))
	_, err = testusers.Encrypt(ctx, c.Keyset(encrypt.KeysetName("payments")), people)
	if !errors.Is(err, errSource) || !errors.Is(err, encrypt.ErrTransport) {
		t.Fatalf("source failure: %v, want the source's error and ErrTransport", err)
	}
	if kms.count("Decrypt") != 0 {
		t.Error("a request was sent without credentials")
	}
	// No secret in the error text.
	if strings.Contains(err.Error(), "fixture-secret") {
		t.Errorf("the error holds a secret: %v", err)
	}
}

func TestKeyVendorOptionsAreCheckedBeforeAnythingResolves(t *testing.T) {
	ctx := context.Background()
	aws := encrypt.AWSKMS{Region: "us-east-1", Credentials: encrypt.AWSCredentialsFromEnv()}
	for _, tc := range []struct {
		name string
		opts []encrypt.ClientOption
	}{
		{"records with no vendor", []encrypt.ClientOption{encrypt.WithKeysetRecords("stack-keyset:AQ")}},
		{"a vendor with no records", []encrypt.ClientOption{encrypt.WithKeyVendor(aws)}},
		{"no region", []encrypt.ClientOption{encrypt.WithKeyVendor(encrypt.AWSKMS{Credentials: aws.Credentials}), encrypt.WithKeysetRecords("r")}},
		{"no credentials", []encrypt.ClientOption{encrypt.WithKeyVendor(encrypt.AWSKMS{Region: "us-east-1"}), encrypt.WithKeysetRecords("r")}},
		{"no Vault address", []encrypt.ClientOption{encrypt.WithKeyVendor(encrypt.VaultTransit{Token: encrypt.StaticAccessToken("t")}), encrypt.WithKeysetRecords("r")}},
		{"no Google token", []encrypt.ClientOption{encrypt.WithKeyVendor(encrypt.GoogleCloudKMS{}), encrypt.WithKeysetRecords("r")}},
		{"no Azure token", []encrypt.ClientOption{encrypt.WithKeyVendor(encrypt.AzureKeyVault{}), encrypt.WithKeysetRecords("r")}},
		{"a short static key", []encrypt.ClientOption{encrypt.WithKeyVendor(encrypt.StaticKey{KeyRef: "k", Key: make([]byte, 16)}), encrypt.WithKeysetRecords("r")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No credentials are given: a check that ran after resolving
			// would fail with ErrNoCredentials or a guest error instead.
			_, err := encrypt.NewClient(ctx, tc.opts...)
			if !errors.Is(err, encrypt.ErrEncoding) {
				t.Fatalf("%v, want ErrEncoding", err)
			}
		})
	}

	// A refused config still consumes a static key, and so does one a
	// later WithKeyVendor replaced.
	first, second := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	_, err := encrypt.NewClient(ctx,
		encrypt.WithKeyVendor(encrypt.StaticKey{KeyRef: "a", Key: first}),
		encrypt.WithKeyVendor(encrypt.StaticKey{KeyRef: "b", Key: second}))
	if !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("%v, want ErrEncoding", err)
	}
	if !bytes.Equal(first, make([]byte, 32)) || !bytes.Equal(second, make([]byte, 32)) {
		t.Error("a static key was not wiped")
	}
}

func TestKeyVendorRecordsAreCheckedAtNewClient(t *testing.T) {
	staticKey := bytes.Repeat([]byte{0x42}, 32)
	for _, tc := range []struct {
		name, code string
		record     string
	}{
		{"another vendor's record", "stack_kms_vendor::foreign_vendor", awsRecord(t, modeDerived, "payments")},
		{"wrapped data keys under the static key", "stack_kms_vendor::mode_unsupported", keysetRecord(randomID(t), recordStatic, modeWrapped, "", "dev-key", []byte{1})},
		{"not a record", "stack_kms_vendor::record_prefix", "payments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := encrypt.NewDeterministicVendorClient(context.Background(), testSeed, refusing{},
				encrypt.StaticKey{KeyRef: "dev-key", Key: append([]byte(nil), staticKey...)}, tc.record)
			if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) {
				t.Skip(err)
			}
			if !errors.Is(err, encrypt.ErrEncoding) {
				t.Fatalf("%v, want ErrEncoding", err)
			}
			encrypt.WantCode(t, err, tc.code)
		})
	}
}

func TestVendorCredentialsDoNotPrintTheirSecrets(t *testing.T) {
	c := encrypt.AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "fixture-secret", SessionToken: "fixture-session"}
	tok := encrypt.AccessToken{Token: "fixture-token"}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(tok), fmt.Sprintf("%#v", tok)} {
		if strings.Contains(s, "fixture") {
			t.Errorf("printed a secret: %s", s)
		}
	}
}

func TestStaticKeyDoesNotPrintItsKey(t *testing.T) {
	// 0xAB prints as 171 in %v and as ab in %x.
	k := encrypt.StaticKey{KeyRef: "dev-key", Key: bytes.Repeat([]byte{0xAB}, 32)}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("vendor", "key", k)
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%x", k), logged.String()} {
		if strings.Contains(s, "171") || strings.Contains(strings.ToLower(s), "abab") {
			t.Errorf("printed the key: %s", s)
		}
		if !strings.Contains(s, "dev-key") && !strings.Contains(s, hex.EncodeToString([]byte("dev-key"))) {
			t.Errorf("lost the key ref: %s", s)
		}
	}
}

// noZeroKMSEnvironment clears every place AutoCredentials would look, so a
// test that passes proves NewClient did not look.
func noZeroKMSEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"CS_CLIENT_ID", "CS_CLIENT_KEY", "CS_CLIENT_ACCESS_KEY", "CS_WORKSPACE_CRN", "CS_ZEROKMS_HOST", "CS_VITUR_HOST", "CS_CONFIG_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("HOME", t.TempDir())
}

// vendorOnlyClient is NewClient with a key vendor backend and no
// credentials, over the embedded guest, or a skip when it is absent.
func vendorOnlyClient(t *testing.T, opts ...encrypt.ClientOption) (*encrypt.Client, error) {
	t.Helper()
	if _, err := encrypt.EmbeddedGuest(); err != nil {
		t.Skip(err)
	}
	c, err := encrypt.NewClient(context.Background(), opts...)
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

func TestVendorOnlyClientWithAStaticKey(t *testing.T) {
	noZeroKMSEnvironment(t)
	ctx := context.Background()
	staticKey := bytes.Repeat([]byte{0x42}, 32)
	record := func(name string) (string, [16]byte) {
		id := randomID(t)
		root := make([]byte, 32)
		_, _ = rand.Read(root)
		return keysetRecord(id, recordStatic, modeDerived, name, "dev-key", staticWrap(t, staticKey, root, recordKeyAAD(id, recordStatic, modeDerived))), id
	}
	first, _ := record("first")
	second, secondID := record("second")
	vendor := func() encrypt.KeyVendor {
		return encrypt.StaticKey{KeyRef: "dev-key", Key: append([]byte(nil), staticKey...)}
	}

	// Two records and no default: there is no default keyset.
	_, err := vendorOnlyClient(t, encrypt.WithKeyVendor(vendor()), encrypt.WithKeysetRecords(first, second))
	if !errors.Is(err, encrypt.ErrNotFound) {
		t.Fatalf("two records and no default: %v, want ErrNotFound", err)
	}

	c, err := vendorOnlyClient(t, encrypt.WithKeyVendor(vendor()), encrypt.WithKeysetRecords(first, second),
		encrypt.WithDefaultKeyset(encrypt.KeysetName("second")))
	if err != nil {
		t.Fatal(err)
	}
	def, err := c.DefaultKeyset().KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if def != encrypt.KeysetID(secondID) {
		t.Fatalf("default keyset %s, want %s", def, encrypt.KeysetID(secondID))
	}
	sealed := roundTrip(t, c, c.DefaultKeyset())
	if v := sealed[0].Email.Ciphertext[0]; v != 2 {
		t.Errorf("leaf format version %d, want 2", v)
	}
	roundTrip(t, c, c.Keyset(encrypt.KeysetName("first")))

	// By id works as well as by name.
	byID, err := vendorOnlyClient(t, encrypt.WithKeyVendor(vendor()), encrypt.WithKeysetRecords(first, second),
		encrypt.WithDefaultKeyset(encrypt.KeysetID(secondID)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, byID.DefaultKeyset(), sealed); err != nil {
		t.Fatalf("the default keyset by id does not open its rows: %v", err)
	}

	// Anything that needs ZeroKMS fails with ErrNoZeroKMS: a keyset no
	// record names, and a row a ZeroKMS keyset sealed.
	if _, err := c.Keyset(encrypt.KeysetName("tenant-a")).KeysetID(ctx); !errors.Is(err, encrypt.ErrNoZeroKMS) {
		t.Errorf("a keyset with no record: %v, want ErrNoZeroKMS", err)
	}
	zerokms, err := testusers.Encrypt(ctx, deterministicClient(t).DefaultKeyset(), people)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, c, zerokms); !errors.Is(err, encrypt.ErrNoZeroKMS) {
		t.Errorf("a ZeroKMS row: %v, want ErrNoZeroKMS", err)
	}
}

func TestVendorOnlyClientWithAWSKMS(t *testing.T) {
	noZeroKMSEnvironment(t)
	kms := &fakeKMS{}
	creds := &countingCredentials{}
	c, err := vendorOnlyClient(t,
		encrypt.WithKeyVendor(encrypt.AWSKMS{Region: "ap-southeast-2", Credentials: creds}),
		encrypt.WithKeysetRecords(awsRecord(t, modeDerived, "payments")),
		encrypt.WithTransport(kms),
		// Keep no root key, so each use of it unwraps it again.
		encrypt.WithRootKeyTTL(0))
	if err != nil {
		t.Fatal(err)
	}
	if n := kms.count("Decrypt"); n != 0 {
		t.Errorf("NewClient made %d vendor calls, want 0", n)
	}
	roundTrip(t, c, c.DefaultKeyset())
	// The Encrypt uses the root key twice (the data keys, then the index
	// key for the terms in the settle); each Decrypt uses it once.
	if n := kms.count("Decrypt"); n != 4 {
		t.Errorf("Decrypt calls: %d, want 4", n)
	}
	if len(kms.failures) > 0 {
		t.Fatalf("the fake KMS saw: %s", strings.Join(kms.failures, "; "))
	}
	if creds.asked != 4 {
		t.Errorf("the credential source was asked %d times, want 4", creds.asked)
	}
}

func TestVendorOnlyOptionsAreChecked(t *testing.T) {
	noZeroKMSEnvironment(t)
	ctx := context.Background()
	static := func() encrypt.KeyVendor {
		return encrypt.StaticKey{KeyRef: "k", Key: make([]byte, 32)}
	}
	for _, tc := range []struct {
		name string
		opts []encrypt.ClientOption
	}{
		{"a default keyset with ZeroKMS credentials", []encrypt.ClientOption{
			encrypt.WithKeyVendor(static()), encrypt.WithKeysetRecords("r"),
			encrypt.WithCredentials(encrypt.AutoCredentials()), encrypt.WithDefaultKeyset(encrypt.KeysetName("a")),
		}},
		{"a default keyset with no vendor", []encrypt.ClientOption{encrypt.WithDefaultKeyset(encrypt.KeysetName("a"))}},
		{"the default selector as the default", []encrypt.ClientOption{
			encrypt.WithKeyVendor(static()), encrypt.WithKeysetRecords("r"), encrypt.WithDefaultKeyset(nil),
		}},
		{"a root key TTL with no vendor", []encrypt.ClientOption{encrypt.WithRootKeyTTL(time.Minute)}},
		{"a negative root key TTL", []encrypt.ClientOption{
			encrypt.WithKeyVendor(static()), encrypt.WithKeysetRecords("r"), encrypt.WithRootKeyTTL(-time.Second),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := encrypt.NewClient(ctx, tc.opts...); !errors.Is(err, encrypt.ErrEncoding) {
				t.Fatalf("%v, want ErrEncoding", err)
			}
		})
	}
}
