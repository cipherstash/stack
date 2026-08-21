ARG PG_VERSION=17
FROM postgres:${PG_VERSION}

# Re-declared after FROM so the value is visible to LABELs below — pre-FROM ARGs
# are scoped to the FROM line itself.
ARG PG_VERSION=17
ARG EQL_VERSION=DEV

LABEL org.opencontainers.image.source="https://github.com/cipherstash/encrypt-query-language"
LABEL org.opencontainers.image.description="PostgreSQL ${PG_VERSION} with CipherStash EQL ${EQL_VERSION} pre-installed"
LABEL org.opencontainers.image.licenses="MPL-2.0"
LABEL com.cipherstash.eql.version="${EQL_VERSION}"
LABEL com.cipherstash.postgres.version="${PG_VERSION}"

# Numeric prefix orders this after any user-supplied init scripts named 00-*.
COPY cipherstash-encrypt.sql /docker-entrypoint-initdb.d/10-cipherstash-encrypt.sql
