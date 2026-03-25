#!/usr/bin/env bash
# Delete the realm specified in .env file (removes all clients, users, roles, scopes).
#
# Usage: ./cleanup.sh
#
# Environment variables (from .env file):
#   KEYCLOAK_URL
#   KEYCLOAK_ADMIN_USERNAME
#   KEYCLOAK_ADMIN_PASSWORD
#   REALM_NAME
set -euo pipefail

# Load environment variables from .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Check required environment variables
if [ -z "$KEYCLOAK_URL" ] || [ -z "$KEYCLOAK_ADMIN_USERNAME" ] || [ -z "$KEYCLOAK_ADMIN_PASSWORD" ] || [ -z "$REALM_NAME" ]; then
    echo "ERROR: Missing required environment variables. Please ensure .env file contains:"
    echo "  KEYCLOAK_URL"
    echo "  KEYCLOAK_ADMIN_USERNAME"
    echo "  KEYCLOAK_ADMIN_PASSWORD"
    echo "  REALM_NAME"
    exit 1
fi

REALM="$REALM_NAME"

echo "Getting admin token from ${KEYCLOAK_URL} ..."
TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=${KEYCLOAK_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" | jq -r '.access_token')

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "ERROR: Failed to get admin token."
    exit 1
fi

echo "Deleting realm '${REALM}' ..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    "${KEYCLOAK_URL}/admin/realms/${REALM}" \
    -H "Authorization: Bearer ${TOKEN}")

if [[ "$HTTP_CODE" == "204" ]]; then
    echo "  Realm '${REALM}' deleted successfully."
elif [[ "$HTTP_CODE" == "404" ]]; then
    echo "  Realm '${REALM}' does not exist (already cleaned up)."
else
    echo "  ERROR: Unexpected response code ${HTTP_CODE} for realm '${REALM}'."
    exit 1
fi

echo "Cleanup complete."
