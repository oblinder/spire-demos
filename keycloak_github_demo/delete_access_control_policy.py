"""Delete access control policy from Keycloak realm.

Removes all composite role mappings from realm roles assigned to users in the config file.
This clears the composite client roles from realm roles (e.g., developer, tech-support)
while keeping the realm role assignments to users intact.

Usage:
    python delete_access_control_policy.py <config.yaml>

Arguments:
    config.yaml    Path to main configuration YAML file

Environment variables (from .env file):
    KEYCLOAK_URL              - Keycloak server URL
    KEYCLOAK_ADMIN_USERNAME   - Admin username
    KEYCLOAK_ADMIN_PASSWORD   - Admin password
    REALM_NAME                - Target realm name

Example:
    # Ensure .env file contains required variables
    python delete_access_control_policy.py config.yaml
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Set

import yaml
from keycloak import KeycloakAdmin
from dotenv import load_dotenv


def load_main_config(config_file: Path) -> Dict[str, Any]:
    """Load main configuration from YAML file."""
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)


def get_realm_role_composites(admin: KeycloakAdmin, realm: str, realm_role_name: str) -> List[Dict[str, Any]]:
    """Get all composite roles for a realm role."""
    try:
        realm_role = admin.get_realm_role(realm_role_name)
        url = (
            f"{admin.connection.base_url}/admin/realms/{realm}"
            f"/roles-by-id/{realm_role['id']}/composites"
        )
        response = admin.connection.raw_get(url)
        
        # Handle different response types from raw_get
        import json
        if hasattr(response, 'json'):
            # It's a Response object
            if response.status_code == 404:
                return []
            response.raise_for_status()
            return response.json()
        elif isinstance(response, bytes):
            return json.loads(response.decode('utf-8'))
        elif isinstance(response, list):
            return response
        else:
            return []
    except Exception as e:
        print(f"  Warning: Could not get composites for role '{realm_role_name}': {e}")
        return []


def remove_all_composites_from_realm_role(
    admin: KeycloakAdmin, realm: str, realm_role_name: str
) -> None:
    """Remove all composite roles from a realm role."""
    try:
        # Get all composite roles
        composite_roles = get_realm_role_composites(admin, realm, realm_role_name)
        
        if not composite_roles:
            print(f"  No composite roles to remove from '{realm_role_name}'")
            return
        
        # Get the realm role
        realm_role = admin.get_realm_role(realm_role_name)
        
        # Remove all composite roles
        url = (
            f"{admin.connection.base_url}/admin/realms/{realm}"
            f"/roles-by-id/{realm_role['id']}/composites"
        )
        admin.connection.raw_delete(url, data=json.dumps(composite_roles))
        
        composite_names = [f"{r.get('clientRole', False) and r.get('containerId', 'client') or 'realm'}.{r['name']}" for r in composite_roles]
        print(f"  ✓ Removed {len(composite_roles)} composite role(s) from '{realm_role_name}': {', '.join(composite_names)}")
    except Exception as e:
        print(f"  ✗ Failed to remove composites from '{realm_role_name}': {e}")


def delete_access_control_policy(
    admin: KeycloakAdmin,
    realm: str,
    config_file: Path
) -> None:
    """Remove all composite role mappings from realm roles used by users in config.
    
    Args:
        admin: Keycloak admin instance
        realm: Realm name
        config_file: Path to main config YAML file
    """
    main_config = load_main_config(config_file)
    users_config = main_config.get('users', [])
    
    if not users_config:
        print("No users found in configuration")
        return
    
    # Collect all unique realm roles assigned to users
    user_realm_roles: Set[str] = set()
    for user_config in users_config:
        roles = user_config.get('roles', [])
        user_realm_roles.update(roles)
    
    if not user_realm_roles:
        print("No realm roles assigned to users in configuration")
        return
    
    print(f"\n=== Removing composite role mappings from {len(user_realm_roles)} realm role(s) ===")
    print(f"Realm roles to process: {', '.join(sorted(user_realm_roles))}")
    
    for realm_role_name in sorted(user_realm_roles):
        print(f"\nProcessing realm role '{realm_role_name}':")
        remove_all_composites_from_realm_role(admin, realm, realm_role_name)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python delete_access_control_policy.py <config.yaml>", file=sys.stderr)
        print("Example: python delete_access_control_policy.py config.yaml", file=sys.stderr)
        sys.exit(1)
    
    config_file_arg = sys.argv[1]
    
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
    
    print(f"Connecting to Keycloak at {KEYCLOAK_URL} ...")
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name=realm_name,
        user_realm_name="master",
    )
    
    # Delete policy
    delete_access_control_policy(admin, realm_name, config_file_path)
    print("\nAccess control policy deletion complete.")

# Made with Bob
