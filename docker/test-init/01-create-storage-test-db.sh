#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE sid_storage_test OWNER sid;
    CREATE DATABASE sid_notify_test OWNER sid;
EOSQL
