"""Setup script for Keycloak RBAC Token Exchange Demo.

Creates a standalone 'rbac-demo' realm with clients, roles, client scopes,
audience mappers, token exchange permissions, and users to demonstrate
role-based access control through OAuth2 token exchange chains.

Architecture:
    User -> demo-ui -> app-alpha -> backend-alpha
                    -> app-beta  -> backend-beta

Usage:
    python setup_rbac_demo.py

Environment variables (all optional):
    KEYCLOAK_URL            (default: http://keycloak.localtest.me:8080)
    KEYCLOAK_ADMIN_USERNAME (default: admin)
    KEYCLOAK_ADMIN_PASSWORD (default: admin)
"""

import json
import os
import sys

from keycloak import KeycloakAdmin, KeycloakPostError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak.localtest.me:8080")
KEYCLOAK_ADMIN_USERNAME = os.environ.get("KEYCLOAK_ADMIN_USERNAME", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
REALM = "rbac-demo"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
        print(f"  Using existing client: {client_id}")
        return internal_id


# ---------------------------------------------------------------------------
# Main setup
# ---------------------------------------------------------------------------


def main():
    print(f"Connecting to Keycloak at {KEYCLOAK_URL} ...")

    # Connect as master admin
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name="master",
        user_realm_name="master",
    )

    # -----------------------------------------------------------------------
    # 1. Create the rbac-demo realm
    # -----------------------------------------------------------------------
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

    # Switch to the new realm
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name=REALM,
        user_realm_name="master",
    )

    # -----------------------------------------------------------------------
    # 2. Create clients
    # -----------------------------------------------------------------------
    print("\n=== Creating clients ===")

    demo_ui_id = create_client_idempotent(
        admin,
        {
            "clientId": "demo-ui",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": True,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": "demo-ui-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    app_alpha_id = create_client_idempotent(
        admin,
        {
            "clientId": "app-alpha",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": "app-alpha-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    backend_alpha_id = create_client_idempotent(
        admin,
        {
            "clientId": "backend-alpha",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": "backend-alpha-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    app_beta_id = create_client_idempotent(
        admin,
        {
            "clientId": "app-beta",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": "app-beta-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    backend_beta_id = create_client_idempotent(
        admin,
        {
            "clientId": "backend-beta",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": "backend-beta-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    # -----------------------------------------------------------------------
    # 3. Create realm roles
    # -----------------------------------------------------------------------
    print("\n=== Creating realm roles ===")
    roles = [
        "app-alpha-access",
        "backend-alpha-access",
        "app-beta-access",
        "backend-beta-access",
    ]
    for role_name in roles:
        try:
            admin.create_realm_role({"name": role_name}, skip_exists=True)
            print(f"  Created role: {role_name}")
        except Exception:
            print(f"  Role {role_name} already exists")

    # -----------------------------------------------------------------------
    # 4. Create client scopes with audience mappers
    # -----------------------------------------------------------------------
    print("\n=== Creating client scopes ===")

    scope_configs = [
        ("app-alpha-audience", "app-alpha", "app-alpha-access"),
        ("backend-alpha-audience", "backend-alpha", "backend-alpha-access"),
        ("app-beta-audience", "app-beta", "app-beta-access"),
        ("backend-beta-audience", "backend-beta", "backend-beta-access"),
    ]

    scope_ids = {}
    for scope_name, target_client, role_name in scope_configs:
        scope_id = admin.create_client_scope(
            {
                "name": scope_name,
                "protocol": "openid-connect",
                "attributes": {
                    "include.in.token.scope": "true",
                    "display.on.consent.screen": "false",
                },
            },
            skip_exists=True,
        )
        scope_ids[scope_name] = scope_id
        print(f"  Created client scope: {scope_name}")

        # Add audience mapper
        try:
            admin.add_mapper_to_client_scope(
                scope_id,
                {
                    "name": f"{target_client}-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": {
                        "included.client.audience": target_client,
                        "introspection.token.claim": "true",
                        "userinfo.token.claim": "false",
                        "id.token.claim": "false",
                        "lightweight.claim": "false",
                        "access.token.claim": "true",
                        "lightweight.access.token.claim": "false",
                    },
                },
            )
            print(f"    Added audience mapper -> {target_client}")
        except Exception as e:
            print(f"    Audience mapper already exists for {target_client}: {e}")

        # Assign realm role to client scope (role-gating)
        assign_realm_role_to_client_scope(admin, REALM, scope_id, role_name)
        print(f"    Assigned role {role_name} to scope {scope_name}")

    # -----------------------------------------------------------------------
    # 5. Assign client scopes to clients
    # -----------------------------------------------------------------------
    print("\n=== Assigning client scopes to clients ===")

    # demo-ui gets app-alpha-audience and app-beta-audience
    admin.add_client_default_client_scope(
        demo_ui_id, scope_ids["app-alpha-audience"], {}
    )
    admin.add_client_default_client_scope(
        demo_ui_id, scope_ids["app-beta-audience"], {}
    )
    print("  demo-ui <- app-alpha-audience, app-beta-audience")

    # app-alpha gets backend-alpha-audience
    admin.add_client_default_client_scope(
        app_alpha_id, scope_ids["backend-alpha-audience"], {}
    )
    print("  app-alpha <- backend-alpha-audience")

    # app-beta gets backend-beta-audience
    admin.add_client_default_client_scope(
        app_beta_id, scope_ids["backend-beta-audience"], {}
    )
    print("  app-beta <- backend-beta-audience")

    # -----------------------------------------------------------------------
    # 6. Token exchange is enabled via client attributes
    # -----------------------------------------------------------------------
    # Token exchange is enabled on all confidential clients via the
    # "standard.token.exchange.enabled": "true" attribute set during
    # client creation. No additional permission configuration needed.

    # -----------------------------------------------------------------------
    # 7. Create users
    # -----------------------------------------------------------------------
    print("\n=== Creating users ===")

    users = {
        "alice": ["app-alpha-access", "backend-alpha-access", "backend-beta-access"],
        "bob": ["app-alpha-access", "app-beta-access", "backend-beta-access"],
        "charlie": [],
    }

    for username, user_roles in users.items():
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

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RBAC Demo realm setup complete!")
    print("=" * 60)
    print(f"\nKeycloak URL:  {KEYCLOAK_URL}")
    print(f"Realm:         {REALM}")
    print(f"Admin console: {KEYCLOAK_URL}/admin/master/console/#/{REALM}")
    print("\nUsers (password='password' for all):")
    print("  alice   - roles: app-alpha-access, backend-alpha-access, backend-beta-access")
    print("  bob     - roles: app-alpha-access, app-beta-access, backend-beta-access")
    print("  charlie - roles: (none)")
    print("\nRun ./run_demo.sh to execute the token exchange demo.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"\nERROR: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
