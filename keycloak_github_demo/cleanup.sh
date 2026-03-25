#!/usr/bin/env bash
# Delete the rbac-demo realm (removes all clients, users, roles, scopes).
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak.localtest.me:9090}"
KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_ADMIN_USERNAME:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM="github-demo"

echo "Deleting realm '${REALM}' from ${KEYCLOAK_URL} ..."

# Get admin token
TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=${KEYCLOAK_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" | jq -r '.access_token')

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "ERROR: Failed to get admin token."
    exit 1
fi

# Delete the realm
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    "${KEYCLOAK_URL}/admin/realms/${REALM}" \
    -H "Authorization: Bearer ${TOKEN}")

if [[ "$HTTP_CODE" == "204" ]]; then
    echo "Realm '${REALM}' deleted successfully."
elif [[ "$HTTP_CODE" == "404" ]]; then
    echo "Realm '${REALM}' does not exist (already cleaned up)."
else
    echo "ERROR: Unexpected response code ${HTTP_CODE}."
    exit 1
fi
