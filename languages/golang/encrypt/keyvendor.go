package encrypt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"golang.org/x/oauth2"
)

// KeyVendor is the one key vendor backend a [Client] can hold beside
// ZeroKMS: [AWSKMS], [GoogleCloudKMS], [AzureKeyVault], [VaultTransit] or
// [StaticKey]. Give it with [WithKeyVendor], and its keyset records with
// [WithKeysetRecords].
//
// A keyset whose record the client holds is sealed and opened through the
// key vendor backend. Every other keyset, and the default keyset, is
// ZeroKMS's. Select a vendor keyset by the name or the id in its record:
// client.Keyset(encrypt.KeysetName("payments")).
//
// The guest makes the vendor requests and signs them. The client's
// RoundTripper ([WithTransport]) sends them. Keys stay in the guest: the
// host supplies only short-lived credentials, never key material. See the
// package documentation for what each backend and key mode can and cannot
// do.
//
// The interface is sealed: the five types above are its only
// implementations.
type KeyVendor interface {
	keyVendor() (*vendorSpec, error)
}

// vendorSpec is a KeyVendor as the client uses it: the config keys the
// guest reads, and where the per-request credential comes from.
type vendorSpec struct {
	// name is the guest's key_vendor value.
	name string
	// id is the KeyVendor byte the guest names in vendor_credential_get.
	id uint32
	// fields are the backend's settings in the guest config.
	fields vcvalue.Object
	// staticKey is StaticKey's key, consumed by NewClient.
	staticKey []byte
	aws       AWSCredentialSource
	token     AccessTokenSource
}

// The KeyVendor bytes of the v2 leaf header and the keyset record. They
// cross the vendor_credential_get import.
const (
	vendorAWS    = 1
	vendorGCP    = 2
	vendorAzure  = 3
	vendorVault  = 4
	vendorStatic = 5
)

// AWSKMS is AWS KMS as the key vendor backend. The key in each keyset
// record is a KMS key ARN. Both key modes.
type AWSKMS struct {
	// Region is the AWS region of the keys, such as "us-east-1". Required.
	Region string
	// Endpoint overrides the regional AWS KMS endpoint, for a VPC endpoint
	// or LocalStack. Empty means https://kms.<region>.amazonaws.com/.
	Endpoint string
	// Credentials supplies temporary AWS credentials, asked before each
	// request. Required. Adapt the AWS SDK's chain with
	// [AWSCredentialsFunc]; [AWSCredentialsFromEnv] reads the environment.
	Credentials AWSCredentialSource
}

func (v AWSKMS) keyVendor() (*vendorSpec, error) {
	if v.Region == "" {
		return nil, fmt.Errorf("%w: AWSKMS needs a Region", ErrEncoding)
	}
	if v.Credentials == nil {
		return nil, fmt.Errorf("%w: AWSKMS needs Credentials", ErrEncoding)
	}
	fields := vcvalue.Object{{Key: "aws_region", Value: v.Region}}
	if v.Endpoint != "" {
		fields = append(fields, vcvalue.Field{Key: "aws_endpoint", Value: v.Endpoint})
	}
	return &vendorSpec{name: "aws-kms", id: vendorAWS, fields: fields, aws: v.Credentials}, nil
}

// GoogleCloudKMS is Google Cloud KMS as the key vendor backend. The key in
// each keyset record is a crypto key name
// (projects/…/locations/…/keyRings/…/cryptoKeys/…). Both key modes.
type GoogleCloudKMS struct {
	// Endpoint overrides https://cloudkms.googleapis.com, for a regional
	// endpoint. Empty means the global one.
	Endpoint string
	// Token supplies an OAuth 2.0 access token with the Cloud KMS scope,
	// asked before each request. Required. [OAuth2AccessTokens] adapts
	// golang.org/x/oauth2/google's default credentials.
	Token AccessTokenSource
}

func (v GoogleCloudKMS) keyVendor() (*vendorSpec, error) {
	if v.Token == nil {
		return nil, fmt.Errorf("%w: GoogleCloudKMS needs a Token source", ErrEncoding)
	}
	var fields vcvalue.Object
	if v.Endpoint != "" {
		fields = append(fields, vcvalue.Field{Key: "gcp_endpoint", Value: v.Endpoint})
	}
	return &vendorSpec{name: "gcp-kms", id: vendorGCP, fields: fields, token: v.Token}, nil
}

// AzureKeyVault is Azure Key Vault or Managed HSM as the key vendor
// backend. The key in each keyset record is a key identifier
// (https://<vault>.vault.azure.net/keys/<name>), which names the vault.
// Both key modes.
type AzureKeyVault struct {
	// Token supplies a Microsoft Entra ID access token for the scope the
	// client asks for: https://vault.azure.net/.default for Key Vault,
	// https://managedhsm.azure.net/.default for Managed HSM. Required.
	// Adapt azidentity with [AccessTokenFunc].
	Token AccessTokenSource
}

func (v AzureKeyVault) keyVendor() (*vendorSpec, error) {
	if v.Token == nil {
		return nil, fmt.Errorf("%w: AzureKeyVault needs a Token source", ErrEncoding)
	}
	return &vendorSpec{name: "azure-key-vault", id: vendorAzure, token: v.Token}, nil
}

// VaultTransit is HashiCorp Vault's Transit secrets engine as the key
// vendor backend. The key in each keyset record is a Transit key name.
// Both key modes.
type VaultTransit struct {
	// Address is the Vault address, such as "https://vault.example.com:8200".
	// Required.
	Address string
	// Namespace is the Vault Enterprise namespace. Empty means none.
	Namespace string
	// Mount is the Transit mount path. Empty means "transit".
	Mount string
	// Token supplies a Vault client token, asked before each request; the
	// scope it is given is empty. Required. Adapt the Vault API client's
	// token with [AccessTokenFunc].
	Token AccessTokenSource
}

func (v VaultTransit) keyVendor() (*vendorSpec, error) {
	if v.Address == "" {
		return nil, fmt.Errorf("%w: VaultTransit needs an Address", ErrEncoding)
	}
	if v.Token == nil {
		return nil, fmt.Errorf("%w: VaultTransit needs a Token source", ErrEncoding)
	}
	fields := vcvalue.Object{{Key: "vault_address", Value: v.Address}}
	if v.Namespace != "" {
		fields = append(fields, vcvalue.Field{Key: "vault_namespace", Value: v.Namespace})
	}
	if v.Mount != "" {
		fields = append(fields, vcvalue.Field{Key: "vault_mount", Value: v.Mount})
	}
	return &vendorSpec{name: "vault-transit", id: vendorVault, fields: fields, token: v.Token}, nil
}

// StaticKey is a 32-byte key the application holds, as the key vendor
// backend: for development, tests, and deployments that keep a key in their
// own secret store. Derived data keys only, because the key is always in
// memory. Nothing outside the process can refuse or audit its use.
type StaticKey struct {
	// KeyRef is the key's reference, as the keyset records name it.
	// Required.
	KeyRef string
	// Key is the key: 32 bytes. NewClient wipes it whatever the outcome,
	// as it consumes the client key: after NewClient returns, the slice
	// holds zeros.
	Key []byte
}

func (v StaticKey) keyVendor() (*vendorSpec, error) {
	if v.KeyRef == "" {
		return nil, fmt.Errorf("%w: StaticKey needs a KeyRef", ErrEncoding)
	}
	if len(v.Key) != 32 {
		return nil, fmt.Errorf("%w: StaticKey's Key is %d bytes, not 32", ErrEncoding, len(v.Key))
	}
	return &vendorSpec{
		name:      "static",
		id:        vendorStatic,
		fields:    vcvalue.Object{{Key: "static_key_ref", Value: v.KeyRef}},
		staticKey: v.Key,
	}, nil
}

// wipeVendorKey zeroes a StaticKey's key, the one key material a KeyVendor
// value holds. Any other KeyVendor holds none.
func wipeVendorKey(v KeyVendor) {
	switch k := v.(type) {
	case StaticKey:
		wipe(k.Key)
	case *StaticKey:
		if k != nil {
			wipe(k.Key)
		}
	}
}

// WithKeyVendor gives the client one key vendor backend. It needs
// [WithKeysetRecords]; one without the other is refused. A later
// WithKeyVendor replaces an earlier one. The default is none: every keyset
// is ZeroKMS's, as before.
//
// A key vendor backend is an alternative to ZeroKMS. With no
// [WithCredentials] the client has no ZeroKMS: NewClient neither needs nor
// looks for ZeroKMS credentials, the default keyset is a vendor keyset (see
// [WithDefaultKeyset]), and a call that needs a ZeroKMS keyset fails with
// [ErrNoZeroKMS]. To hold both, also give WithCredentials, for example
// WithCredentials(AutoCredentials()).
func WithKeyVendor(v KeyVendor) ClientOption {
	return func(o *clientOptions) {
		if o.keyVendor != nil {
			o.supersededVendors = append(o.supersededVendors, o.keyVendor)
		}
		o.keyVendor = v
	}
}

// WithKeysetRecords gives the keyset records of the client's key vendor
// backend: the "stack-keyset:…" texts that `stash keyset` writes, one per
// keyset. Each record names its keyset id, its name, the vendor key, its key
// mode and its wrapped key; none holds a key in the clear. Every record must
// be of the backend [WithKeyVendor] gives, and two records may not share an
// id or a name. Records add up across calls.
func WithKeysetRecords(records ...string) ClientOption {
	return func(o *clientOptions) { o.keysetRecords = append(o.keysetRecords, records...) }
}

// WithDefaultKeyset names the default keyset of a client that has a key
// vendor backend and no ZeroKMS: the keyset [Client.DefaultKeyset] and every
// call that names no keyset use. Name it by the name or the id in its keyset
// record, as [Client.Keyset] does: [KeysetName] or [KeysetID]. With one
// keyset record it is that record's keyset and this option is not needed;
// with several and no default, NewClient fails with [ErrNotFound].
//
// A client with ZeroKMS has the default keyset its ZeroKMS administrator
// set, and refuses this option with [ErrEncoding].
func WithDefaultKeyset(sel KeysetSelector) ClientOption {
	return func(o *clientOptions) { o.defaultKeyset, o.defaultKeysetSet = sel, true }
}

// WithRootKeyTTL sets how long the guest keeps a keyset's root key
// unwrapped under derived data keys, after which the next use unwraps it
// again: one vendor call, which the vendor can refuse. Zero keeps none:
// each use of a root key unwraps it, so an Encrypt that also derives search
// terms unwraps it twice. The default is 5 minutes. It has
// no effect on wrapped data keys, which keep nothing beyond one call.
// Negative, or with no [WithKeyVendor], is refused with [ErrEncoding].
func WithRootKeyTTL(d time.Duration) ClientOption {
	return func(o *clientOptions) { o.rootKeyTTL = &d }
}

// checkVendorOnlyOptions refuses the options that need a key vendor
// backend, or a client with no ZeroKMS, when the client has not got one.
func checkVendorOnlyOptions(cfg *clientOptions, vendorOnly bool) error {
	if cfg.rootKeyTTL != nil {
		if cfg.keyVendor == nil {
			return fmt.Errorf("%w: WithRootKeyTTL needs WithKeyVendor", ErrEncoding)
		}
		if *cfg.rootKeyTTL < 0 {
			return fmt.Errorf("%w: WithRootKeyTTL must not be negative", ErrEncoding)
		}
	}
	if !cfg.defaultKeysetSet {
		return nil
	}
	if !vendorOnly {
		return fmt.Errorf("%w: WithDefaultKeyset needs WithKeyVendor and no WithCredentials: a client with ZeroKMS has the default keyset its administrator set", ErrEncoding)
	}
	switch cfg.defaultKeyset.(type) {
	case KeysetName, KeysetID:
		return nil
	default:
		return fmt.Errorf("%w: WithDefaultKeyset takes a KeysetName or a KeysetID", ErrEncoding)
	}
}

// noZeroKMS is the Credentials of a client that has a key vendor backend
// and no ZeroKMS: nothing to resolve, no client key and no token.
type noZeroKMS struct{}

func (noZeroKMS) resolve(context.Context, resolveOptions) (*resolvedCredentials, error) {
	return &resolvedCredentials{}, nil
}

// keyVendorConfig checks the key vendor options host-side, before anything
// is resolved, and renders them. Nil when no backend is configured.
func keyVendorConfig(v KeyVendor, records []string) (*vendorSpec, error) {
	if v == nil {
		if len(records) > 0 {
			return nil, fmt.Errorf("%w: WithKeysetRecords needs WithKeyVendor", ErrEncoding)
		}
		return nil, nil
	}
	spec, err := v.keyVendor()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: WithKeyVendor needs WithKeysetRecords", ErrEncoding)
	}
	return spec, nil
}

// configFields renders the backend and its records as guest config keys.
// The result holds a StaticKey's key: the caller wipes what it encodes.
func (s *vendorSpec) configFields(records []string) vcvalue.Object {
	fields := vcvalue.Object{
		{Key: "key_vendor", Value: s.name},
		{Key: "keyset_records", Value: append([]string(nil), records...)},
	}
	fields = append(fields, s.fields...)
	if s.staticKey != nil {
		fields = append(fields, vcvalue.Field{Key: "static_key", Value: s.staticKey})
	}
	return fields
}

// ErrNoKeyVendorCredentials is a credential source with nothing to give,
// such as [AWSCredentialsFromEnv] with the variables unset. The wrapped
// error says what to set.
var ErrNoKeyVendorCredentials = errors.New("encrypt: no key vendor credentials")

// AWSCredentials are temporary AWS credentials: what the guest signs an
// AWS KMS request with (SigV4). Long-term access keys work too, with no
// SessionToken, but prefer the temporary credentials of a role.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	// SessionToken is the session token of temporary credentials.
	SessionToken string
	// Expires is when the credentials expire. Zero means unknown; the guest
	// refuses credentials whose expiry has passed.
	Expires time.Time
}

// String hides the secret and the session token.
func (c AWSCredentials) String() string {
	return fmt.Sprintf("encrypt.AWSCredentials{AccessKeyID: %s, SecretAccessKey: <redacted>, SessionToken: <redacted>, Expires: %s}", c.AccessKeyID, c.Expires)
}

// GoString hides them from %#v too.
func (c AWSCredentials) GoString() string { return c.String() }

// LogValue hides them from slog.
func (c AWSCredentials) LogValue() slog.Value {
	return slog.GroupValue(slog.String("access_key_id", c.AccessKeyID), slog.Time("expires", c.Expires))
}

// AWSCredentialSource supplies [AWSCredentials]. The client asks before
// each AWS KMS request, so a source that fetches should cache, as the AWS
// SDK's chain does. It is called with the client's lock held; it must not
// call the client.
type AWSCredentialSource interface {
	AWSCredentials(ctx context.Context) (AWSCredentials, error)
}

// AWSCredentialsFunc adapts a function to an [AWSCredentialSource]. With
// the AWS SDK for Go v2 (github.com/aws/aws-sdk-go-v2/config), whose
// credentials cache refreshes before expiry:
//
//	cfg, err := config.LoadDefaultConfig(ctx)
//	// ...
//	creds := encrypt.AWSCredentialsFunc(func(ctx context.Context) (encrypt.AWSCredentials, error) {
//		c, err := cfg.Credentials.Retrieve(ctx)
//		return encrypt.AWSCredentials{
//			AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey,
//			SessionToken: c.SessionToken, Expires: c.Expires,
//		}, err
//	})
type AWSCredentialsFunc func(ctx context.Context) (AWSCredentials, error)

// AWSCredentials calls f.
func (f AWSCredentialsFunc) AWSCredentials(ctx context.Context) (AWSCredentials, error) {
	return f(ctx)
}

// AWSCredentialsFromEnv reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
// AWS_SESSION_TOKEN on each request. Without the first two it fails with
// [ErrNoKeyVendorCredentials]. For anything else (a role, IRSA, IMDS, SSO)
// use the AWS SDK's chain through [AWSCredentialsFunc].
func AWSCredentialsFromEnv() AWSCredentialSource {
	return AWSCredentialsFunc(func(context.Context) (AWSCredentials, error) {
		c := AWSCredentials{
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		}
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return AWSCredentials{}, fmt.Errorf("%w: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY", ErrNoKeyVendorCredentials)
		}
		return c, nil
	})
}

// AccessToken is a short-lived bearer token for a key vendor backend: a
// Google OAuth 2.0 access token, a Microsoft Entra ID access token, or a
// Vault client token.
type AccessToken struct {
	Token string
	// Expires is when the token expires. Zero means unknown; the guest
	// refuses a token whose expiry has passed.
	Expires time.Time
}

// String hides the token.
func (t AccessToken) String() string {
	return fmt.Sprintf("encrypt.AccessToken{Token: <redacted>, Expires: %s}", t.Expires)
}

// GoString hides it from %#v too.
func (t AccessToken) GoString() string { return t.String() }

// LogValue hides it from slog.
func (t AccessToken) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("expires", t.Expires))
}

// AccessTokenSource supplies an [AccessToken] for scope. The client asks
// before each vendor request, so a source that fetches should cache. Azure
// asks for the scope of the vault the key is in; Google Cloud asks for
// https://www.googleapis.com/auth/cloudkms; Vault asks with an empty scope.
// It is called with the client's lock held; it must not call the client.
type AccessTokenSource interface {
	AccessToken(ctx context.Context, scope string) (AccessToken, error)
}

// AccessTokenFunc adapts a function to an [AccessTokenSource]. With azidentity
// (github.com/Azure/azure-sdk-for-go/sdk/azidentity), whose credentials
// cache tokens:
//
//	cred, err := azidentity.NewDefaultAzureCredential(nil)
//	// ...
//	tokens := encrypt.AccessTokenFunc(func(ctx context.Context, scope string) (encrypt.AccessToken, error) {
//		t, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
//		return encrypt.AccessToken{Token: t.Token, Expires: t.ExpiresOn}, err
//	})
//
// With the Vault API client (github.com/hashicorp/vault/api), after a
// login method has set its token:
//
//	tokens := encrypt.AccessTokenFunc(func(context.Context, string) (encrypt.AccessToken, error) {
//		return encrypt.AccessToken{Token: vault.Token()}, nil
//	})
type AccessTokenFunc func(ctx context.Context, scope string) (AccessToken, error)

// AccessToken calls f.
func (f AccessTokenFunc) AccessToken(ctx context.Context, scope string) (AccessToken, error) {
	return f(ctx, scope)
}

// OAuth2AccessTokens adapts a golang.org/x/oauth2 token source, such as
// Google's default credentials, to an [AccessTokenSource]. The scope is
// the source's own, set when it was made, so the scope asked for is not
// passed on:
//
//	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloudkms")
//	// ...
//	tokens := encrypt.OAuth2AccessTokens(creds.TokenSource)
//
// Wrap a source that fetches in oauth2.ReuseTokenSource, as
// google.FindDefaultCredentials does, so that each request does not fetch.
func OAuth2AccessTokens(source oauth2.TokenSource) AccessTokenSource {
	return AccessTokenFunc(func(context.Context, string) (AccessToken, error) {
		if source == nil {
			return AccessToken{}, errors.New("encrypt: nil oauth2 token source")
		}
		t, err := source.Token()
		if err != nil {
			return AccessToken{}, err
		}
		return AccessToken{Token: t.AccessToken, Expires: t.Expiry}, nil
	})
}

// StaticAccessToken is a source that always gives token, with no expiry:
// for a token from `gcloud auth print-access-token`, a Vault token in
// VAULT_TOKEN, or a test. It is used until the vendor refuses it.
func StaticAccessToken(token string) AccessTokenSource {
	return AccessTokenFunc(func(context.Context, string) (AccessToken, error) {
		return AccessToken{Token: token}, nil
	})
}

// vendorCredential asks the backend's source for the credential the guest
// asked for, and renders it as the guest reads it. The result holds a
// secret; the caller wipes it.
func (s *vendorSpec) vendorCredential(ctx context.Context, vendor uint32, scope string) ([]byte, error) {
	if vendor != s.id {
		return nil, fmt.Errorf("encrypt: the guest asked for a credential of key vendor %d, but the client's is %s", vendor, s.name)
	}
	var fields vcvalue.Object
	var expires time.Time
	switch {
	case s.aws != nil:
		c, err := s.aws.AWSCredentials(ctx)
		if err != nil {
			return nil, err
		}
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return nil, fmt.Errorf("%w: the AWS credential source returned no access key id or secret", ErrNoKeyVendorCredentials)
		}
		fields = vcvalue.Object{
			{Key: "access_key_id", Value: c.AccessKeyID},
			{Key: "secret_access_key", Value: c.SecretAccessKey},
		}
		if c.SessionToken != "" {
			fields = append(fields, vcvalue.Field{Key: "session_token", Value: c.SessionToken})
		}
		expires = c.Expires
	case s.token != nil:
		t, err := s.token.AccessToken(ctx, scope)
		if err != nil {
			return nil, err
		}
		if t.Token == "" {
			return nil, fmt.Errorf("%w: the %s token source returned an empty token", ErrNoKeyVendorCredentials, s.name)
		}
		fields = vcvalue.Object{{Key: "token", Value: t.Token}}
		expires = t.Expires
	default:
		return nil, fmt.Errorf("encrypt: the %s key backend takes no credentials", s.name)
	}
	if !expires.IsZero() {
		fields = append(fields, vcvalue.Field{Key: "expires_at", Value: expires.Unix()})
	}
	return vcffi.Marshal(fields)
}
