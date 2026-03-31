"""Export Keycloak access control policy to access_control_policy.yaml format.

Reads the current Keycloak realm configuration and generates an access_control_policy.yaml
file that maps realm roles to client roles based on composite role relationships.

Usage:
    python export_access_control_policy.py [realm_name] [output_file]

Arguments:
    realm_name    Optional: Name of the realm to export (default: from REALM_NAME env var)
    output_file   Optional: Output file path (default: exported_access_control_policy.yaml)

Environment variables (from .env file):
    KEYCLOAK_URL
    KEYCLOAK_ADMIN_USERNAME
    KEYCLOAK_ADMIN_PASSWORD
    REALM_NAME (used if realm_name argument not provided)
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Any
import yaml
from keycloak import KeycloakAdmin
from dotenv import load_dotenv


def get_realm_role_composites(admin: KeycloakAdmin, realm: str, role_name: str) -> List[Dict[str, str]]:
    """Get composite client roles for a realm role."""
    try:
        url = f"{admin.connection.base_url}/admin/realms/{realm}/roles/{role_name}/composites"
        response = admin.connection.raw_get(url)
        
        # Handle different response types from raw_get
        import json
        if hasattr(response, 'json'):
            # It's a Response object
            if response.status_code == 404:
                # No composites exist for this role
                return []
            response.raise_for_status()
            composites = response.json()
        elif isinstance(response, bytes):
            composites = json.loads(response.decode('utf-8'))
        else:
            composites = response
        
        # Ensure composites is a list
        if not isinstance(composites, list):
            print(f"  Warning: Unexpected response type for role {role_name}: {type(composites)}")
            return []
        
        client_roles = []
        for composite in composites:
            # Only include client roles (not realm roles)
            if isinstance(composite, dict) and composite.get('clientRole', False):
                client_id = composite.get('containerId')
                role_name_composite = composite.get('name')
                
                # Get client name from client ID
                if client_id and role_name_composite:
                    try:
                        client = admin.get_client(client_id)
                        client_name = client['clientId']
                        
                        client_roles.append({
                            'client': client_name,
                            'role': role_name_composite
                        })
                    except Exception:
                        pass
        
        return client_roles
    except Exception as e:
        print(f"  Warning: Could not get composites for role {role_name}: {e}")
        return []


def get_realm_roles(admin: KeycloakAdmin) -> List[str]:
    """Get all realm roles, excluding default Keycloak roles."""
    try:
        roles = admin.get_realm_roles()
        # Filter out default Keycloak roles
        default_roles = {'default-roles-', 'offline_access', 'uma_authorization'}
        custom_roles = []
        for role in roles:
            role_name = role['name']
            # Skip default roles and roles that start with default-roles-
            if not any(role_name.startswith(dr) or role_name == dr for dr in default_roles):
                custom_roles.append(role_name)
        return custom_roles
    except Exception as e:
        print(f"  Warning: Could not get realm roles: {e}")
        return []


def export_access_control_policy(realm_name: str, output_file: str):
    """Export Keycloak access control policy to YAML format."""
    script_dir = Path(__file__).parent
    
    # Load environment variables from .env file
    load_dotenv(script_dir / '.env')
    
    KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
    KEYCLOAK_ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME")
    KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
    
    if not all([KEYCLOAK_URL, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD]):
        raise ValueError("Missing required environment variables. Please ensure .env file contains KEYCLOAK_URL, KEYCLOAK_ADMIN_USERNAME, and KEYCLOAK_ADMIN_PASSWORD")
    
    print(f"\nConnecting to Keycloak at {KEYCLOAK_URL} ...")
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name="master",
        user_realm_name="master",
    )
    
    # Switch to target realm
    print(f"Switching to realm: {realm_name}")
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name=realm_name,
        user_realm_name="master",
    )
    
    # Get realm roles
    print("\n=== Exporting access control policy ===")
    realm_roles = get_realm_roles(admin)
    
    if not realm_roles:
        print("  No custom realm roles found")
        print("  Creating empty policy file")
        policy = {}
    else:
        print(f"  Found {len(realm_roles)} custom realm roles")
        
        policy = {}
        for role_name in realm_roles:
            print(f"  Analyzing role: {role_name}")
            
            # Get composite client roles
            client_roles = get_realm_role_composites(admin, realm_name, role_name)
            
            if client_roles:
                policy[role_name] = client_roles
                print(f"    -> {len(client_roles)} client role mappings")
                for cr in client_roles:
                    print(f"       - {cr['client']}.{cr['role']}")
            else:
                print(f"    -> No client role mappings")
    
    # Write to YAML file
    print(f"\n=== Writing policy to {output_file} ===")
    
    yaml_content = "# Access Control Policy - Exported\n"
    yaml_content += "# Maps user roles (realm roles) to specific client roles\n"
    yaml_content += "# Client roles are defined as {client_name}-{role} based on config.yaml\n\n"
    yaml_content += "# Format: user_role_name -> list of client roles\n"
    yaml_content += "# Each entry specifies: client (client name) and role (role name from that client)\n"
    yaml_content += "# You CAN map a realm role to multiple roles of the same client by listing them separately\n\n"
    
    yaml_content += yaml.dump({'policy': policy}, default_flow_style=False, sort_keys=False)
    
    with open(output_file, 'w') as f:
        f.write(yaml_content)
    
    print(f"✓ Access control policy exported successfully to {output_file}")
    print(f"\nExported:")
    print(f"  - {len(policy)} realm role mappings")
    total_mappings = sum(len(mappings) for mappings in policy.values())
    print(f"  - {total_mappings} total client role assignments")
    print(f"\nYou can now use this file with setup_demo.py")


def main():
    """Main entry point."""
    # Load environment variables from .env file first
    script_dir = Path(__file__).parent
    load_dotenv(script_dir / '.env')
    
    # Default values
    realm_name = os.getenv("REALM_NAME", "demo")
    output_file = "exported_access_control_policy.yaml"
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        realm_name = sys.argv[1]
    
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    print(f"Exporting access control policy from realm: {realm_name}")
    print(f"Output file: {output_file}")
    
    export_access_control_policy(realm_name, output_file)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"\nERROR: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

# Made with Bob
