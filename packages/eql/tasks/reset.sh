#!/bin/bash
#MISE description="Uninstall and install EQL to local postgres"
#USAGE flag "--postgres <version>" help="Run tests for specified Postgres version" default="17" {
#USAGE   choices "14" "15" "16" "17"
#USAGE }

set -euo pipefail

fail_if_postgres_not_running () {
  containers=$(docker ps --filter "name=^${container_name}$" --quiet)
  if [ -z "${containers}" ]; then
    echo "error: Docker container for PostgreSQL is not running"
    echo "error: Try running 'mise run postgres:up ${container_name}' to start the container"
    exit 65
  fi
}

POSTGRES_VERSION=${usage_postgres}

connection_url=postgresql://${POSTGRES_USER:-$USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
container_name=postgres-${POSTGRES_VERSION}

# Setup
fail_if_postgres_not_running

# Uninstall
cat release/cipherstash-encrypt-uninstall.sql | docker exec -i ${container_name} psql ${connection_url} -f-

# Wipe test data
cat tasks/reset.sql | docker exec -i ${container_name} psql ${connection_url} -f-
