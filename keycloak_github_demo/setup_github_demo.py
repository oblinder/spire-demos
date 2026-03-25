"""Setup script for Keycloak RBAC Token Exchange Demo.

Creates a standalone 'github-demo' realm with clients, roles, client scopes,
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
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak.localtest.me:9090")
KEYCLOAK_ADMIN_USERNAME = os.environ.get("KEYCLOAK_ADMIN_USERNAME", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
REALM = "github-demo"

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


def assign_client_role_to_client_scope(
    admin: KeycloakAdmin, realm: str, scope_id: str, client_id: str, role_name: str
):
    """Assign a client role to a client scope's scope-mappings."""
    role = admin.get_client_role(client_id, role_name)
    url = (
        f"{admin.connection.base_url}/admin/realms/{realm}"
        f"/client-scopes/{scope_id}/scope-mappings/clients/{client_id}"
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
    # 1. Create the github-demo realm
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

    demo_ui_name = "demo-ui"
    demo_ui_id = create_client_idempotent(
        admin,
        {
            "clientId": demo_ui_name,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": True,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": demo_ui_name+"-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    agent_name = "github-agent"
    agent_id = create_client_idempotent(
        admin,
        {
            "clientId": agent_name,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": agent_name+"-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    source_tool_name = "github-source-tool"
    source_tool_id = create_client_idempotent(
        admin,
        {
            "clientId": source_tool_name,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": source_tool_name+"-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    issues_tool_name = "github-issues-tool"
    issues_tool_id = create_client_idempotent(
        admin,
        {
            "clientId": issues_tool_name,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "fullScopeAllowed": False,
            "secret": issues_tool_name+"-secret",
            "attributes": {
                "standard.token.exchange.enabled": "true",
            },
        },
    )

    # -----------------------------------------------------------------------
    # 3. Create client roles
    # -----------------------------------------------------------------------
    print("\n=== Creating client roles ===")
    agent_access_role = agent_name+"-access"
    try:
        admin.create_client_role(
            agent_id,
            {"name": agent_access_role, "clientRole": True},
            skip_exists=True
        )
        print(f"  Created client role: {agent_access_role}")
    except Exception as e:
        print(f"  Client role {agent_access_role} already exists: {e}")

    source_access_role = source_tool_name+"-access"
    try:
        admin.create_client_role(
            source_tool_id,
            {"name": source_access_role, "clientRole": True},
            skip_exists=True
        )
        print(f"  Created client role: {source_access_role}")
    except Exception as e:
        print(f"  Client role {source_access_role} already exists: {e}")

    issues_access_role = issues_tool_name+"-access"
    try:
        admin.create_client_role(
            issues_tool_id,
            {"name": issues_access_role, "clientRole": True},
            skip_exists=True
        )
        print(f"  Created client role: {issues_access_role}")
    except Exception as e:
        print(f"  Client role {issues_access_role} already exists: {e}")

    # -----------------------------------------------------------------------
    # 4. Create realm roles
    # -----------------------------------------------------------------------
    print("\n=== Creating realm roles ===")
    developer_role = "developer"
    tech_support_role = "tech-support"
    sales_role = "sales"
    client_roles = [
        developer_role,
        tech_support_role,
        sales_role
    ]
    for role_name in client_roles:
        try:
            admin.create_realm_role({"name": role_name}, skip_exists=True)
            print(f"  Created role: {role_name}")
        except Exception:
            print(f"  Role {role_name} already exists")

    # -----------------------------------------------------------------------
    # 5. Map client roles to developer realm role
    # -----------------------------------------------------------------------
    print("\n=== Mapping client roles to realm roles ===")
    
    # Get the client roles
    agent_access_role_id = admin.get_client_role(
        agent_id, agent_access_role
    )
    source_access_role_id = admin.get_client_role(
        source_tool_id, source_access_role
    )
    issues_access_role_id = admin.get_client_role(
        issues_tool_id, issues_access_role
    )
    
    # Add client roles as composites to the developer realm role
    try:
        admin.add_composite_realm_roles_to_role(
            developer_role,
            [agent_access_role_id, source_access_role_id, issues_access_role_id]
        )
        print(f"  Mapped {[agent_access_role, source_access_role, issues_access_role]} to '{developer_role}' role")
    except Exception as e:
        print(f"  Client roles may already be mapped: {e}")

    # Add client roles as composites to the tech-support realm role
    try:
        admin.add_composite_realm_roles_to_role(
            tech_support_role,
            [agent_access_role_id, issues_access_role_id]
        )
        print(f"  Mapped {[agent_access_role, issues_access_role]} to '{tech_support_role}' role")
    except Exception as e:
        print(f"  Client roles may already be mapped: {e}")

    # -----------------------------------------------------------------------
    # 6. Create client scopes with audience mappers
    # -----------------------------------------------------------------------
    print("\n=== Creating client scopes ===")

    # Map client names to their internal IDs
    client_name_to_id = {
        agent_name: agent_id,
        source_tool_name: source_tool_id,
        issues_tool_name: issues_tool_id
    }

    scope_configs = [
        (agent_name+"-audience", agent_name, agent_access_role),
        (source_tool_name+"-audience", source_tool_name, source_access_role),
        (issues_tool_name+"-audience", issues_tool_name, issues_access_role)
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

        # Assign client role to client scope (role-gating)
        # Get the internal client ID from the client name
        target_client_id = client_name_to_id[target_client]
        assign_client_role_to_client_scope(admin, REALM, scope_id, target_client_id, role_name)
        print(f"    Assigned role {role_name} to scope {scope_name}")

    # -----------------------------------------------------------------------
    # 7. Assign target client scopes to caller clients
    # -----------------------------------------------------------------------
    print("\n=== Assigning client scopes to clients ===")

    # demo-ui gets github-agent-audience
    admin.add_client_default_client_scope(
        demo_ui_id, scope_ids[agent_name+"-audience"], {}
    )
    print(f"  {demo_ui_name} <- {agent_name}-audience")

    # github-agent gets github-source-tool-audience
    admin.add_client_default_client_scope(
        agent_id, scope_ids[source_tool_name+"-audience"], {}
    )
    print(f"  {agent_name} <- {source_tool_name}-audience")

    # github-agent gets github-issues-tool-audience
    admin.add_client_default_client_scope(
        agent_id, scope_ids[issues_tool_name+"-audience"], {}
    )
    print(f"  {agent_name} <- {issues_tool_name}-audience")

    # -----------------------------------------------------------------------
    # 8. Token exchange is enabled via client attributes
    # -----------------------------------------------------------------------
    # Token exchange is enabled on all confidential clients via the
    # "standard.token.exchange.enabled": "true" attribute set during
    # client creation. No additional permission configuration needed.

    # -----------------------------------------------------------------------
    # 8. Create users
    # -----------------------------------------------------------------------
    print("\n=== Creating users ===")

    users = {
        "alice": [developer_role],
        "bob": [tech_support_role],
        "charlie": [sales_role],
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
    print("Github Demo realm setup complete!")
    print("=" * 60)
    print(f"\nKeycloak URL:  {KEYCLOAK_URL}")
    print(f"Realm:         {REALM}")
    print(f"Admin console: {KEYCLOAK_URL}/admin/master/console/#/{REALM}")
    print("\nUsers (password='password' for all):")
    print("  alice (developer)    - roles: github-agent-access, github-source-tool-access, github-issues-tool-access")
    print("  bob   (tech support) - roles: github-agent-access, github-source-tool-access")
    print("  charlie (sales)      - roles: (none)")
    print("\nRun ./run_demo.sh to execute the token exchange demo.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"\nERROR: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
