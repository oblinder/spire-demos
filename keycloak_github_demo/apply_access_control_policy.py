"""Apply access control policy to Keycloak realm.

Loads scope-to-role mappings from a policy file and applies them to client scopes.
This implements role-based gating for token exchange by assigning realm roles to
client scopes via scope-mappings. Only users with the required role will get the
corresponding audience claim in their tokens.

Usage:
    python apply_access_control_policy.py <policy_file.yaml>

Arguments:
    policy_file.yaml    Path to access control policy YAML file

Environment variables (from .env file):
    KEYCLOAK_URL              - Keycloak server URL
    KEYCLOAK_ADMIN_USERNAME   - Admin username
    KEYCLOAK_ADMIN_PASSWORD   - Admin password
    REALM_NAME                - Target realm name

Example:
    # Ensure .env file contains required variables
    python apply_access_control_policy.py scope_configs.yaml
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict

import yaml
from keycloak import KeycloakAdmin
from dotenv import load_dotenv


def load_access_control_policy(access_control_policy_file: Path) -> Dict[str, list]:
    """Load access control policy (scope name -> realm role(s) mappings).
    
    Returns a dictionary where each scope name maps to a list of role names.
    Supports both single role (string) and multiple roles (list) in the YAML file.
    """
    if not access_control_policy_file.exists():
        raise FileNotFoundError(f"Access control policy file not found: {access_control_policy_file}")
    
    with open(access_control_policy_file, 'r') as f:
        policy_config = yaml.safe_load(f)
    
    policy = policy_config.get('policy', {})
    
    # Normalize policy to always use lists
    normalized_policy = {}
    for scope_name, roles in policy.items():
        if isinstance(roles, str):
            # Single role as string - convert to list
            normalized_policy[scope_name] = [roles]
        elif isinstance(roles, list):
            # Already a list
            normalized_policy[scope_name] = roles
        else:
            raise ValueError(f"Invalid role specification for scope '{scope_name}': must be string or list")
    
    return normalized_policy


def assign_realm_role_to_client_scope(
    admin: KeycloakAdmin, realm: str, scope_id: str, role_name: str
):
    """Assign a realm role to a client scope's scope-mappings."""
    role = admin.get_realm_role(role_name)
    url = (
        f"{admin.connection.base_url}/admin/realms/{realm}"
        f"/client-scopes/{scope_id}/scope-mappings/realm"
    )
    admin.connection.raw_post(url, data=json.dumps([role]))


def get_scope_ids(admin: KeycloakAdmin, config_file: Path) -> Dict[str, str]:
    """Get scope IDs from config file's scope_to_client mapping."""
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    scope_to_client = config.get('scope_to_client', {})
    
    # Get all client scopes and build a mapping
    client_scopes = admin.get_client_scopes()
    scope_ids = {}
    
    for scope_name in scope_to_client.keys():
        for scope in client_scopes:
            if scope['name'] == scope_name:
                scope_ids[scope_name] = scope['id']
                break
    
    return scope_ids


def apply_access_control_policy(
    admin: KeycloakAdmin,
    realm: str,
    access_control_policy_file: Path,
    scope_ids: Dict[str, str]
) -> None:
    """Load and apply access control policy to client scopes.
    
    Assigns one or more realm roles to each client scope. Users with ANY of the
    assigned roles will get the corresponding audience claim in their tokens.
    """
    scope_to_roles = load_access_control_policy(access_control_policy_file)
    
    print("\n=== Applying scope-to-role mappings ===")
    for scope_name, role_names in scope_to_roles.items():
        if scope_name in scope_ids:
            scope_id = scope_ids[scope_name]
            for role_name in role_names:
                assign_realm_role_to_client_scope(admin, realm, scope_id, role_name)
                print(f"  Assigned role '{role_name}' to scope '{scope_name}'")
        else:
            print(f"  Warning: Scope '{scope_name}' not found in created scopes")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python apply_access_control_policy.py <config_file.yaml> <access_control_policy.yaml>", file=sys.stderr)
        print("Example: python apply_access_control_policy.py config.yaml scope_configs.yaml", file=sys.stderr)
        sys.exit(1)
    
    config_file_arg = sys.argv[1]
    policy_file_arg = sys.argv[2]
    
    # Load environment variables from .env file
    script_dir = Path(__file__).parent
    load_dotenv(script_dir / '.env')
    
    KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
    KEYCLOAK_ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME")
    KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
    realm_name = os.getenv("REALM_NAME")
    
    if not all([KEYCLOAK_URL, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD, realm_name]):
        raise ValueError("Missing required environment variables. Please ensure .env file contains KEYCLOAK_URL, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD, and REALM_NAME")
    
    # Type assertions after validation
    assert isinstance(KEYCLOAK_URL, str)
    assert isinstance(KEYCLOAK_ADMIN_USERNAME, str)
    assert isinstance(KEYCLOAK_ADMIN_PASSWORD, str)
    assert isinstance(realm_name, str)
    
    config_file_path = script_dir / config_file_arg
    policy_file_path = script_dir / policy_file_arg
    
    print(f"Connecting to Keycloak at {KEYCLOAK_URL} ...")
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name=realm_name,
        user_realm_name="master",
    )
    
    # Get scope IDs from config
    scope_ids = get_scope_ids(admin, config_file_path)
    
    # Apply policy
    apply_access_control_policy(admin, realm_name, policy_file_path, scope_ids)
    print("\nAccess control policy application complete.")

# Made with Bob
