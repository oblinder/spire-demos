"""Setup script for Keycloak Token Exchange Demo.

Creates a realm with clients, roles, client scopes, audience mappers,
and users to demonstrate role-based access control through OAuth2 token exchange.

Usage:
    python setup_demo.py <config_file.yaml> <access_control_policy.yaml>

Arguments:
    config_file.yaml              Path to main configuration YAML file
    access_control_policy.yaml    Path to access control policy YAML file

Environment variables (from .env file):
    KEYCLOAK_URL
    KEYCLOAK_ADMIN_USERNAME
    KEYCLOAK_ADMIN_PASSWORD
    REALM_NAME

Configuration files:
    .env                          - Keycloak connection settings and realm name
    config.yaml                   - Main configuration (clients, roles, users, scope_to_client)
    access_control_policy.yaml    - Access control policy (scope -> required role mappings)
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

import yaml
from keycloak import KeycloakAdmin, KeycloakPostError
from dotenv import load_dotenv

from apply_access_control_policy import apply_access_control_policy

def load_main_config(config_file: Path) -> Dict[str, Any]:
    """Load main configuration from YAML file."""
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def get_config_value(config: Dict[str, Any], *keys, default=None, env_var=None) -> Any:
    """Get configuration value with fallback to environment variable and default."""
    if env_var and os.environ.get(env_var):
        return os.environ.get(env_var)
    
    # Navigate through nested keys
    value = config
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    
    return value if value != config else default


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


def create_client_idempotent(admin: KeycloakAdmin, payload: dict) -> str:
    """Create a client or return existing internal ID."""
    client_id = payload["clientId"]
    try:
        internal_id = admin.create_client(payload)
        print(f"  Created client: {client_id}")
        return internal_id
    except KeycloakPostError:
        internal_id = admin.get_client_id(client_id)
        if internal_id is None:
            raise ValueError(f"Client '{client_id}' not found and could not be created")
        print(f"  Using existing client: {client_id}")
        return internal_id

def create_single_client_scope(
    admin: KeycloakAdmin,
    scope_name: str,
    target_client: str,
    default_attributes: Dict[str, str],
    default_mapper_config: Dict[str, str]
) -> str:
    """Create client scope with audience mapper."""
    # Convert snake_case to dot.notation for Keycloak
    keycloak_attributes = {
        key.replace('_', '.'): value
        for key, value in default_attributes.items()
    }
    
    scope_id = admin.create_client_scope(
        {
            "name": scope_name,
            "protocol": "openid-connect",
            "attributes": keycloak_attributes,
        },
        skip_exists=True,
    )
    print(f"  Created client scope: {scope_name}")

    # Add audience mapper
    try:
        # Convert snake_case to dot.notation for Keycloak
        keycloak_mapper_config = {
            key.replace('_', '.'): value
            for key, value in default_mapper_config.items()
        }
        keycloak_mapper_config["included.client.audience"] = target_client
        
        admin.add_mapper_to_client_scope(
            scope_id,
            {
                "name": f"{target_client}-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": keycloak_mapper_config,
            },
        )
        print(f"    Added audience mapper -> {target_client}")
    except Exception as e:
        print(f"    Audience mapper already exists for {target_client}: {e}")
    
    return scope_id


def main(config_file: str, access_control_policy_file: str):
    """Main setup function."""
    script_dir = Path(__file__).parent
    
    # Load environment variables from .env file
    load_dotenv(script_dir / '.env')
    
    # Load main configuration
    main_config_path = script_dir / config_file
    print(f"Loading main configuration from {main_config_path} ...")
    main_config = load_main_config(main_config_path)
    
    scope_to_client = main_config.get('scope_to_client', {})
    scope_configs = list(scope_to_client.items())
    access_control_policy_path = script_dir / access_control_policy_file
    
    KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
    KEYCLOAK_ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME")
    KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
    REALM = os.getenv("REALM_NAME")
    
    if not all([KEYCLOAK_URL, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD, REALM]):
        raise ValueError("Missing required environment variables. Please ensure .env file contains KEYCLOAK_URL, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD, and REALM_NAME")
    
    # Type assertions after validation
    assert isinstance(KEYCLOAK_URL, str)
    assert isinstance(KEYCLOAK_ADMIN_USERNAME, str)
    assert isinstance(KEYCLOAK_ADMIN_PASSWORD, str)
    assert isinstance(REALM, str)
    
    print(f"\nConnecting to Keycloak at {KEYCLOAK_URL} ...")
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name="master",
        user_realm_name="master",
    )

    # Create realm
    print(f"\n=== Creating realm: {REALM} ===")
    try:
        admin.create_realm(
            {
                "realm": REALM,
                "enabled": True,
                "accessTokenLifespan": 600,
                "verifyEmail": False,
                "registrationEmailAsUsername": False,
            }
        )
        print(f"  Created realm: {REALM}")
    except KeycloakPostError:
        print(f"  Realm {REALM} already exists, continuing...")

    # Switch to realm
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name=REALM,
        user_realm_name="master",
    )

    # Create clients
    print("\n=== Creating clients ===")
    clients_config = main_config['clients']
    
    client_ids = {}
    for client_config in clients_config:
        client_id = client_config['client_id']
        
        client_secret = f"{client_id}-secret"
        
        direct_access_enabled = (client_id == "demo-ui")
        
        client_payload = {
            "clientId": client_id,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": direct_access_enabled,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": client_secret,
            "attributes": {
                "standard.token.exchange.enabled": "true"
            }
        }
        
        internal_id = create_client_idempotent(admin, client_payload)
        print(f"    Secret: {client_secret}")
        if direct_access_enabled:
            print(f"    Direct access grants: enabled")
        
        client_ids[client_id] = {
            'id': internal_id,
            'secret': client_secret
        }

    # Create realm roles
    print("\n=== Creating realm roles ===")
    roles = main_config['realm_roles']
    for role_name in roles:
        try:
            admin.create_realm_role({"name": role_name}, skip_exists=True)
            print(f"  Created role: {role_name}")
        except Exception:
            print(f"  Role {role_name} already exists")

    # Create client scopes with audience mappers
    print("\n=== Creating client scopes ===")
    default_attributes = {
        "include_in_token_scope": "true",
        "display_on_consent_screen": "false",
    }
    default_mapper_config = {
        "introspection_token_claim": "true",
        "userinfo_token_claim": "false",
        "id_token_claim": "false",
        "lightweight_claim": "false",
        "access_token_claim": "true",
        "lightweight_access_token_claim": "false",
    }

    scope_ids = {}
    for scope_name, target_client in scope_configs:
        scope_id = create_single_client_scope(
            admin, scope_name, target_client,
            default_attributes, default_mapper_config
        )
        scope_ids[scope_name] = scope_id
    
    apply_access_control_policy(admin, REALM, access_control_policy_path, scope_ids)

    # Assign client scopes to clients
    print("\n=== Assigning client scopes to clients ===")
    client_scope_assignments = main_config.get('client_scope_assignments', {})
    
    for client_id, scope_names in client_scope_assignments.items():
        if client_id in client_ids and scope_names:
            for scope_name in scope_names:
                if scope_name in scope_ids:
                    admin.add_client_default_client_scope(
                        client_ids[client_id]['id'], scope_ids[scope_name], {}
                    )
            print(f"  {client_id} <- {', '.join(scope_names)}")
        elif client_id in client_ids:
            print(f"  {client_id} <- (no scopes)")

    # Create users
    print("\n=== Creating users ===")
    users_config = main_config['users']

    for user_config in users_config:
        username = user_config['username']
        user_roles = user_config.get('roles', [])
        user_id = admin.create_user(
            {
                "username": username,
                "email": f"{username}@example.com",
                "firstName": username.capitalize(),
                "lastName": "Demo",
                "enabled": True,
                "emailVerified": True,
                "credentials": [
                    {
                        "type": "password",
                        "value": "password",
                        "temporary": False,
                    }
                ],
            },
            exist_ok=True,
        )
        print(f"  Created user: {username}")

        if user_roles:
            role_representations = [
                admin.get_realm_role(r) for r in user_roles
            ]
            try:
                admin.assign_realm_roles(user_id, role_representations)
                print(f"    Assigned roles: {', '.join(user_roles)}")
            except Exception as e:
                print(f"    Roles may already be assigned: {e}")
        else:
            print(f"    No roles assigned")

    # Summary
    print("\n" + "=" * 60)
    print("Demo realm setup complete!")
    print("=" * 60)
    print(f"\nKeycloak URL:  {KEYCLOAK_URL}")
    print(f"Realm:         {REALM}")
    print(f"Admin console: {KEYCLOAK_URL}/admin/master/console/#/{REALM}")
    print("\nUsers (password from config):")
    for user_config in users_config:
        username = user_config['username']
        user_roles = user_config.get('roles', [])
        if user_roles:
            print(f"  {username:8} - roles: {', '.join(user_roles)}")
        else:
            print(f"  {username:8} - roles: (none)")
    print("\nRun ./run_demo.sh to execute the token exchange demo.")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            print("Usage: python setup_demo.py <config_file.yaml> <access_control_policy.yaml>", file=sys.stderr)
            print("Example: python setup_demo.py config.yaml scope_configs.yaml", file=sys.stderr)
            sys.exit(1)
        
        config_file = sys.argv[1]
        access_control_policy_file = sys.argv[2]
        main(config_file, access_control_policy_file)
    except Exception as e:
        import traceback
        print(f"\nERROR: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

