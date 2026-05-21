FROM postgres:latest

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*

# EQL install script, pinned to match the EQL payload format the code emits
# (protect-ffi 0.21.x -> EQL 2.2). Bump in lockstep with protect-ffi.
ARG EQL_VERSION=eql-2.2.1
RUN curl -sLo /tmp/cipherstash-encrypt.sql https://github.com/cipherstash/encrypt-query-language/releases/download/${EQL_VERSION}/cipherstash-encrypt.sql

# Copy the custom entrypoint script and SQL files
COPY postgres-entrypoint.sh /usr/local/bin/postgres-entrypoint.sh
COPY create-ci-table.sql /tmp/create-ci-table.sql

# Make the entrypoint script executable
RUN chmod +x /usr/local/bin/postgres-entrypoint.sh

# Use the custom entrypoint
ENTRYPOINT ["/usr/local/bin/postgres-entrypoint.sh"]

