#!/usr/bin/env bash
# Apply access control policy to the realm specified in .env file.
# Applies scope-to-role mappings from the policy file to client scopes.
#
# Usage: ./apply_policy.sh [policy_file]
#
# Arguments:
#   policy_file  Path to access control policy YAML file (default: scope_configs.yaml)
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

# Check required environment variable
if [ -z "$REALM_NAME" ]; then
    echo "ERROR: Missing required environment variable REALM_NAME. Please ensure .env file contains it."
    exit 1
fi

POLICY_FILE="${1:-scope_configs.yaml}"

echo "Applying access control policy from '${POLICY_FILE}' to realm '${REALM_NAME}' ..."
python apply_access_control_policy.py "${POLICY_FILE}"

if [ $? -eq 0 ]; then
    echo "Access control policy applied successfully to realm '${REALM_NAME}'."
else
    echo "ERROR: Failed to apply access control policy to realm '${REALM_NAME}'."
    exit 1
fi

# Made with Bob
