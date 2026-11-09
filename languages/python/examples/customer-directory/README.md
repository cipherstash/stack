# Customer directory

This is an internal example of the `stackencrypt` Python SDK. It is a FastAPI service that stores customers in PostgreSQL.

| Field | Stored as |
|---|---|
| `email` | Encrypted, with exact-match search |
| `name` | Encrypted, with no search |
| `plan` | Plaintext |
| `created_at` | Plaintext |

The SDK is not released, so its API can change. This example installs the SDK from this checkout.

## Before you start

You need Docker, mise, and a Rust toolchain. mise installs the toolchain.

You also need CipherStash credentials. Set `CS_CLIENT_ACCESS_KEY`, `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, and `CS_CLIENT_KEY`. Or log in with `stash auth login`.

## Run it

Run these commands from this folder.

`mise run setup` deletes this example's database and creates it again. Nothing else is deleted.

```sh
mise run setup
mise run dev
```

Add a customer, then find the customer by exact email:

```sh
curl -X POST http://127.0.0.1:8000/customers \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","name":"Ada Lovelace","plan":"free"}'

curl -X POST http://127.0.0.1:8000/customers/search \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com"}'

curl 'http://127.0.0.1:8000/customers?limit=10'
```

The search is a `POST` so that the email stays out of URLs and access logs.

## Run the tests

The tests use the real ZeroKMS service and the example's PostgreSQL. They empty the `customers` table. CI does not run them.

```sh
mise run test
```
