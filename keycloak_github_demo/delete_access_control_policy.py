"""Delete access control policy from Keycloak realm.

Removes all scope-to-role mappings from client scopes in the specified realm.
This effectively removes the role-based gating for token exchange by clearing
the scope-mappings that control audience claim inclusion.

Usage:
    python delete_access_control_policy.py

Environment variables (from .env file):
    KEYCLOAK_URL              - Keycloak server URL
    KEYCLOAK_ADMIN_USERNAME   - Admin username
    KEYCLOAK_ADMIN_PASSWORD   - Admin password
    REALM_NAME                - Target realm name

Example:
    # Ensure .env file contains required variables
    python delete_access_control_policy.py
"""

import json
import os
import sys
from pathlib import Path

from keycloak import KeycloakAdmin
from dotenv import load_dotenv


def delete_access_control_policy(admin: KeycloakAdmin, realm: str) -> None:
    """Remove all scope-to-role mappings in the realm."""
    print("\n=== Removing all scope-to-role mappings ===")
    
    client_scopes = admin.get_client_scopes()
    
    for scope in client_scopes:
        scope_id = scope['id']
        scope_name = scope['name']
        
        url = (
            f"{admin.connection.base_url}/admin/realms/{realm}"
            f"/client-scopes/{scope_id}/scope-mappings/realm"
        )
        try:
            role_mappings = admin.connection.raw_get(url).json()
            
            if role_mappings:
                admin.connection.raw_delete(url, data=json.dumps(role_mappings))
                print(f"  Removed {len(role_mappings)} role mapping(s) from scope '{scope_name}'")
        except Exception as e:
            print(f"  Warning: Could not remove mappings from scope '{scope_name}': {e}")


if __name__ == "__main__":
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
    
    print(f"Connecting to Keycloak at {KEYCLOAK_URL} ...")
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name=realm_name,
        user_realm_name="master",
    )
    
    delete_access_control_policy(admin, realm_name)
    print("\nAccess control policy deletion complete.")

# Made with Bob
