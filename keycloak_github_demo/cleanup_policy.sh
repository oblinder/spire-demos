#!/usr/bin/env bash
# Remove access control policy from the realm specified in .env file.
# Removes all composite role mappings from realm roles assigned to users.
#
# Usage: ./cleanup_policy.sh [config_file]
#
# Arguments:
#   config_file  Path to configuration YAML file (default: config.yaml)
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

echo "Removing access control policy from realm '${REALM_NAME}' ..."
python delete_access_control_policy.py "${CONFIG_FILE}"

if [ $? -eq 0 ]; then
    echo "Access control policy cleanup complete for realm '${REALM_NAME}'."
else
    echo "ERROR: Failed to remove access control policy from realm '${REALM_NAME}'."
    exit 1
fi

# Made with Bob
