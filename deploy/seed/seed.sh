#!/usr/bin/env bash
# Seed internal OAuth2 clients for the structured.world ecosystem.
#
# Prerequisites:
#   1. CE database (sid) is running and migrated
#   2. SaaS database (sid_saas) has been bootstrapped (structured.id org exists)
#
# Environment variables:
#   CE_DATABASE_URL     — PostgreSQL URL for CE database (default: localhost:54320/sid)
#   SAAS_DATABASE_URL   — PostgreSQL URL for SaaS database (default: localhost:54322/sid_saas)
#
# Usage:
#   ./deploy/seed/seed.sh                    # Uses defaults (local dev)
#   CE_DATABASE_URL=... SAAS_DATABASE_URL=... ./deploy/seed/seed.sh  # Production

set -euo pipefail

CE_DB="${CE_DATABASE_URL:-postgres://sid:sid_dev@localhost:54320/sid}"
SAAS_DB="${SAAS_DATABASE_URL:-postgres://sid:sid_dev@localhost:54322/sid_saas}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Looking up structured.id org_id from SaaS database..."
ORG_ID=$(psql "${SAAS_DB}" -tAc \
  "SELECT id FROM shared.organizations WHERE domain = 'structured.id'" 2>/dev/null)

if [ -z "${ORG_ID}" ]; then
  echo "ERROR: structured.id org not found in SaaS database."
  echo "  Run sid-saas-central first to bootstrap the org."
  exit 1
fi

echo "  org_id = ${ORG_ID}"

echo "==> Seeding 6 internal OAuth2 clients into CE database..."
psql "${CE_DB}" \
  -v org_id="'${ORG_ID}'" \
  -f "${SCRIPT_DIR}/seed_internal_clients.sql"

echo "==> Verifying seeded clients..."
COUNT=$(psql "${CE_DB}" -tAc \
  "SELECT COUNT(*) FROM oauth2_clients WHERE org_id = '${ORG_ID}'")

echo "  ${COUNT} clients with org_id=${ORG_ID}"

if [ "${COUNT}" -lt 6 ]; then
  echo "WARNING: Expected 6 clients, found ${COUNT}"
  exit 1
fi

echo "==> Done. All 6 internal clients seeded."
