"""Apply access control policy to Keycloak realm.

Loads user role to client role mappings from a policy file and applies them as
composite role mappings. This implements role-based access control by making
realm roles (user roles) composites of client roles.

Usage:
    python apply_access_control_policy.py <config_file.yaml> <access_control_policy.yaml>

Arguments:
    config_file.yaml              Path to configuration YAML file
    access_control_policy.yaml    Path to access control policy YAML file

Environment variables (from .env file):
    KEYCLOAK_URL              - Keycloak server URL
    KEYCLOAK_ADMIN_USERNAME   - Admin username
    KEYCLOAK_ADMIN_PASSWORD   - Admin password
    REALM_NAME                - Target realm name

Example:
    # Ensure .env file contains required variables
    python apply_access_control_policy.py config.yaml access_control_policy.yaml
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from keycloak import KeycloakAdmin
from dotenv import load_dotenv


def load_access_control_policy(access_control_policy_file: Path) -> Dict[str, List[Dict[str, str]]]:
    """Load access control policy (user role -> client roles).
    
    Returns a dictionary where each user role (realm role) maps to a list of client role mappings.
    Each mapping contains 'client' (client name) and 'role' (role name).
    """
    if not access_control_policy_file.exists():
        raise FileNotFoundError(f"Access control policy file not found: {access_control_policy_file}")
    
    with open(access_control_policy_file, 'r') as f:
        policy_config = yaml.safe_load(f)
    
    policy = policy_config.get('policy', {})
    
    # Validate policy structure
    for user_role, client_roles in policy.items():
        if not isinstance(client_roles, list):
            raise ValueError(f"Invalid policy for user role '{user_role}': must be a list of client role mappings")
        for client_role in client_roles:
            if not isinstance(client_role, dict):
                raise ValueError(f"Invalid client role mapping for user role '{user_role}': must be a dict with 'client' and 'role' keys")
            if 'client' not in client_role or 'role' not in client_role:
                raise ValueError(f"Invalid client role mapping for user role '{user_role}': must contain 'client' and 'role' keys")
            if not isinstance(client_role['client'], str) or not isinstance(client_role['role'], str):
                raise ValueError(f"Invalid client role mapping for user role '{user_role}': 'client' and 'role' must be strings")
    
    return policy


def get_client_ids(admin: KeycloakAdmin) -> Dict[str, str]:
    """Get mapping of client names to client IDs."""
    clients = admin.get_clients()
    return {client['clientId']: client['id'] for client in clients}


def add_client_role_to_realm_role_composite(
    admin: KeycloakAdmin, realm: str, realm_role_name: str, client_id: str, client_role_name: str
):
    """Add a client role to a realm role's composite roles."""
    # Get the client role
    client_role = admin.get_client_role(client_id, client_role_name)
    
    # Get the realm role
    realm_role = admin.get_realm_role(realm_role_name)
    
    # Add client role to realm role's composites
    url = (
        f"{admin.connection.base_url}/admin/realms/{realm}"
        f"/roles-by-id/{realm_role['id']}/composites"
    )
    admin.connection.raw_post(url, data=json.dumps([client_role]))


def add_client_scope_to_realm_role(
    admin: KeycloakAdmin, realm: str, realm_role_name: str, scope_id: str
):
    """Add a client scope to a realm role's scope mappings."""
    # Get the realm role
    realm_role = admin.get_realm_role(realm_role_name)
    
    # Add client scope to realm role's scope mappings
    url = (
        f"{admin.connection.base_url}/admin/realms/{realm}"
        f"/roles-by-id/{realm_role['id']}/scope-mappings/client-scopes/{scope_id}"
    )
    admin.connection.raw_put(url, data=json.dumps([]))


def apply_access_control_policy(
    admin: KeycloakAdmin,
    realm: str,
    access_control_policy_file: Path,
    client_ids: Dict[str, str],
    scope_ids: Optional[Dict[str, str]] = None
) -> None:
    """Load and apply access control policy to realm roles.
    
    Makes realm roles composites of client roles and assigns client scopes to realm roles.
    This restricts tokens to only include the client roles and scopes mapped to the user's realm roles.
    
    Args:
        admin: Keycloak admin instance
        realm: Realm name
        access_control_policy_file: Path to policy YAML file
        client_ids: Mapping of client names to client IDs
        scope_ids: Mapping of scope names to scope IDs
    """
    user_role_to_client_roles = load_access_control_policy(access_control_policy_file)
    
    # Step 1: Make realm roles composites of client roles
    # This ensures users with realm roles automatically get the mapped client roles
    print("\n=== Making realm roles composites of client roles ===")
    for user_role, client_role_mappings in user_role_to_client_roles.items():
        print(f"\nProcessing realm role '{user_role}':")
        for mapping in client_role_mappings:
            client_name = mapping['client']
            role_name = mapping['role']
            
            if client_name not in client_ids:
                print(f"  Warning: Client '{client_name}' not found")
                continue
            
            client_id = client_ids[client_name]
            
            try:
                add_client_role_to_realm_role_composite(admin, realm, user_role, client_id, role_name)
                print(f"  ✓ Added client role '{client_name}.{role_name}' to realm role '{user_role}'")
            except Exception as e:
                print(f"  ℹ Client role '{client_name}.{role_name}' already in composite or error: {e}")
    
    # Skip realm role to client scope mappings
    # These interfere with client role-based filtering
    print("\n=== Skipping realm role to client scope mappings ===")
    print("  (Relying only on client role-based scope filtering)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python apply_access_control_policy.py <config_file.yaml> <access_control_policy.yaml>", file=sys.stderr)
        print("Example: python apply_access_control_policy.py config.yaml access_control_policy.yaml", file=sys.stderr)
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
    
    # Get client IDs
    client_ids = get_client_ids(admin)
    
    # Apply policy
    apply_access_control_policy(admin, realm_name, policy_file_path, client_ids)
    print("\nAccess control policy application complete.")

# Made with Bob
