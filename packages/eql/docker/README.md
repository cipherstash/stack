# `postgres-eql` Docker image

A layered image that ships an official `postgres` image with [CipherStash EQL](https://github.com/cipherstash/encrypt-query-language) pre-installed. One `docker run` and you have a Postgres with the `eql_v3` schema, types, and operators ready to use.

## Quick start

```sh
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres \
  ghcr.io/cipherstash/postgres-eql:17
```

Then in another shell:

```sh
PGPASSWORD=postgres psql -h localhost -U postgres -c "SELECT eql_v3.version();"
```

## Tags

Images are published to `ghcr.io/cipherstash/postgres-eql` on every EQL GitHub release.

| Tag                  | Resolves to                                 |
| -------------------- | ------------------------------------------- |
| `latest`             | latest EQL on PostgreSQL 17                 |
| `<eql_version>`      | that EQL version on PostgreSQL 17           |
| `<pg_version>`       | latest EQL on that PostgreSQL major         |
| `<pg_version>-<eql>` | that EQL version on that PostgreSQL major   |

Supported PostgreSQL majors: `14`, `15`, `16`, `17`.
Architectures: `linux/amd64`, `linux/arm64`.

Examples:

```sh
docker pull ghcr.io/cipherstash/postgres-eql:latest
docker pull ghcr.io/cipherstash/postgres-eql:17-<eql-version>  # pin a specific EQL release
docker pull ghcr.io/cipherstash/postgres-eql:14
```

## How it works

EQL is pure SQL, so the image just drops the release SQL into the base `postgres` image's init directory:

```
COPY cipherstash-encrypt.sql /docker-entrypoint-initdb.d/10-cipherstash-encrypt.sql
```

The official `postgres` entrypoint runs every `*.sql` file in `/docker-entrypoint-initdb.d/` **on first boot of an empty data directory**. That means:

- Fresh container, fresh volume → EQL is installed automatically.
- Mounting a pre-existing data directory → EQL is **not** installed (the entrypoint skips init when the data dir is already populated). Install EQL manually with `psql -f cipherstash-encrypt.sql` against the existing database.

The numeric prefix (`10-`) leaves room for users to drop their own `00-*.sql` files alongside EQL if they want to run setup before EQL initializes.

## Building locally

From the repo root:

```sh
mise run build --version <eql-version>
cp release/cipherstash-encrypt.sql docker/
docker build \
  --build-arg PG_VERSION=17 \
  --build-arg EQL_VERSION=<eql-version> \
  -t postgres-eql:dev \
  docker/
```

## See also

- [Main EQL README](../README.md) — usage, configuration, and SQL API
- [CipherStash Proxy](https://github.com/cipherstash/proxy) and [CipherStash Stack](https://github.com/cipherstash/stack) — the clients that actually encrypt and decrypt data
