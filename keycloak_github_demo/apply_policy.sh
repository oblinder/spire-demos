#!/usr/bin/env bash
# Apply access control policy to the realm specified in .env file.
# Makes realm roles composites of client roles based on the policy file.
#
# Usage: ./apply_policy.sh [config_file] [policy_file]
#
# Arguments:
#   config_file  Path to configuration YAML file (default: config.yaml)
#   policy_file  Path to access control policy YAML file (default: access_control_policy.yaml)
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

CONFIG_FILE="${1:-config.yaml}"
POLICY_FILE="${2:-access_control_policy.yaml}"

echo "Applying access control policy from '${POLICY_FILE}' to realm '${REALM_NAME}' ..."
python apply_access_control_policy.py "${CONFIG_FILE}" "${POLICY_FILE}"

if [ $? -eq 0 ]; then
    echo "Access control policy applied successfully to realm '${REALM_NAME}'."
else
    echo "ERROR: Failed to apply access control policy to realm '${REALM_NAME}'."
    exit 1
fi

# Made with Bob
