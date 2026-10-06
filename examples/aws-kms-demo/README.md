# aws-kms-demo

`stack-encrypt` encrypting and decrypting a value with **AWS KMS** as the key
provider instead of ZeroKMS.

The chain has three pieces. None of them is specific to this demo:

| Piece | Role |
| --- | --- |
| `vitaminc_kms::AwsDataKeySource<32>` | A data key source bound to one AWS KMS key. It is a `vitaminc-kms` `KeyProvider<32>`. |
| `stack_encrypt::registry::FixedIndexKeySource` | Pairs that source with the persisted `KeyId` of the keyset's index key, so it is also an `IndexKeyProvider<32>`. |
| `stack_encrypt::registry::StaticKeysetRegistry` | stack-encrypt's registry over a fixed table of keysets. Here the table has one keyset, which is the default. |

`StackCipher` is then built over that registry, in the same way as over
ZeroKMS. The same chain works for Azure Key Vault, Cloud KMS and Vault
Transit: turn on the vendor feature of `vitaminc-kms` and use that vendor's
data key source.

## Running it

LocalStack Community's `kms` service is sufficient. You do not need a Pro
tier or an AWS account:

```sh
docker compose -f examples/aws-kms-demo/docker-compose.yml up -d
cd examples/aws-kms-demo && mise x -- cargo run
docker compose -f examples/aws-kms-demo/docker-compose.yml down
```

LocalStack binds to `127.0.0.1` only, because it accepts any credentials.

If nothing listens on `localhost:4566`, the demo prints a skip notice and
exits with success. Every other failure is an error and exits with a
failure. This includes an AWS KMS that refuses the first call (`ListKeys`),
for example because of bad credentials or an IAM policy.

| Variable | Effect |
| --- | --- |
| `AWS_KMS_DEMO_ENDPOINT_URL` | The KMS endpoint. Unset: LocalStack at `http://localhost:4566`, with fake credentials. Empty: the AWS SDK's own endpoint, region and credentials. |
| `AWS_KMS_DEMO_KEY_ID` | The AWS KMS key that the keyset is bound to. Unset: the demo creates a new symmetric key. |
| `AWS_KMS_DEMO_INDEX_KEY_ID` | The persisted index `KeyId`, as hex. Unset: the demo provisions a new one. It needs `AWS_KMS_DEMO_KEY_ID`. |

To run against a real AWS account, set `AWS_KMS_DEMO_ENDPOINT_URL` to an empty
string. Supply credentials with `kms:ListKeys`, `kms:GenerateDataKey` and
`kms:Decrypt`, and `kms:CreateKey` if you do not set `AWS_KMS_DEMO_KEY_ID`.

## How the index key's `KeyId` is provisioned

stack-encrypt derives each keyset's equality, match and order terms from one
**index key**. On ZeroKMS the service derives that key from the keyset. AWS
KMS has no deterministic derivation, so the index key is an ordinary data key
that is stored once and read back on every run:

1. **Provision once.** Call `GenerateDataKey` one time on the keyset's AWS
   KMS key. Keep only the result's `key_id`. That is the `CiphertextBlob`,
   which is the data key that AWS KMS encrypted. Do not keep the plaintext.
2. **Persist the `KeyId`.** Store it with the keyset's configuration, for
   example in a configuration file or a secrets store. It is encrypted, but
   it is as important as the AWS KMS key itself: if you lose it, all of the
   keyset's index terms become unfindable.
3. **Read it back on every run.** Give it to `FixedIndexKeySource::new`.
   When the cipher loads the keyset, it decrypts that `KeyId` with AWS KMS,
   and the result is the index key.

Do not provision a new `KeyId` at startup. A new `KeyId` gives a new index
key, and then no index term written before matches a query.

The demo does step 1 when `AWS_KMS_DEMO_INDEX_KEY_ID` is unset, and it prints
the two values to set for the next run. With both values set, it skips steps
1 and 2 and reads the index key back, as a deployment does.

The keyset's id (`KEYSET_ID` in `src/main.rs`) is configuration too. Every
leaf sealed under the keyset carries it, so choose it once and keep it with
the AWS KMS key and the index `KeyId`.

## Why this is a separate crate

It is detached from the root cargo workspace. Its `Cargo.toml` has its own
`[workspace]` table, the same as `languages/golang/stackencrypt/guest`, and the
root `Cargo.toml` lists it in `exclude`.

CI builds and tests the root workspace with `--all-features`, and no feature
gate can hide a feature from that. An AWS feature on a workspace member would
put the AWS SDK in *every* workspace build. `aws-smithy-http-client` turns on
`serde_json/preserve_order`, which, under cargo's feature unification, changes
the JSON map order for every other crate in the workspace and breaks snapshot
tests.

Detached, this crate resolves its own dependency graph in its own
`Cargo.lock`. It builds with the Rust toolchain that the root `mise.toml`
pins. Its `vitaminc-kms` dependency must use the same git source and `rev` as
stack-encrypt's. Otherwise cargo builds two copies, and `AwsDataKeySource`
does not implement the `KeyProvider` trait that stack-encrypt uses.
