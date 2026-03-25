# Keycloak RBAC Token Exchange Demo

A standalone teaching demo that illustrates Keycloak role-based access control (RBAC) through OAuth2 token exchange. This demo shows how roles gate access at each stage of a multi-hop token exchange chain.

## Overview

This demo creates a self-contained realm in Keycloak (default: `github-demo`) with a 2-stage token exchange architecture. Users obtain tokens through a chain of exchanges, where each stage requires specific realm roles. Without the required role, the audience claim is not included in the token, causing the exchange to fail.

## Architecture

```
                      ┌─────────────────┐     ┌──────────────────────┐
                 ┌───►│  github-agent   ├────►│ github-tool-partial  │
                 │    └─────────────────┘     └──────────────────────┘
┌────────────┐   │    Stage 1                  Stage 2
│  demo-ui   ├───┤    (needs github-agent-     (needs github-tool-
│(confidential)  │     access role)              partial-access role)
└────────────┘   │
  User login     │
                 │    ┌─────────────────┐     ┌──────────────────────┐
                 └───►│  github-agent   ├────►│ github-tool-full     │
                      └─────────────────┘     └──────────────────────┘
                      Stage 1                  Stage 3
                      (needs github-agent-     (needs github-tool-
                       access role)              full-access role)
```

**Token exchange flow (2-3 stages):**
- **Stage 1:** User logs in via `demo-ui`, exchanges token for `github-agent`
  (requires `github-agent-access` role for audience inclusion)
- **Stage 2:** Exchange `github-agent` token for `github-tool-partial`
  (requires `github-tool-partial-access` role for audience inclusion)
- **Stage 3:** Exchange `github-agent` token for `github-tool-full`
  (requires `github-tool-full-access` role for audience inclusion)

**Role-gating mechanism:** Each client scope has a corresponding realm role
assigned via scope-mappings. The audience claim is only included in the token
if the user has the required role. Without the audience claim, the token
exchange fails because the subject_token won't list the target client as
audience.

## Users and Expected Results

| User    | Roles                                                   |
|---------|---------------------------------------------------------|
| alice   | `github-agent-access`, `github-tool-partial-access`, `github-tool-full-access` |
| bob     | `github-agent-access`, `github-tool-partial-access`      |
| charlie | *(none)*                                                |

| User    | Agent | Tool-Partial | Tool-Full |
|---------|-------|--------------|-----------|
| alice   | PASS  | PASS         | PASS      |
| bob     | PASS  | PASS         | FAIL      |
| charlie | FAIL  | -            | -         |

**Why:**
- **Alice** has all roles and can complete the full token exchange chain to both partial and full tool access.
- **Bob** can reach the agent and partial tool but cannot access the full tool (missing `github-tool-full-access`).
- **Charlie** has no roles so all exchanges fail at Stage 1.

## Prerequisites

### Keycloak Instance

This demo requires a running Keycloak instance. You have several options:

#### Option 1: Use Keycloak from Kagenti Kind Cluster (Recommended for Development)

If you have the [Kagenti platform](https://github.com/kagenti/kagenti) deployed on a Kind cluster, it includes a Keycloak instance at `http://keycloak.localtest.me:8080` (default admin/admin).

To set up Kagenti:

```bash
git clone https://github.com/kagenti/kagenti
cd kagenti
./.github/scripts/local-setup/kind-full-test.sh --skip-cluster-destroy
```

The demo defaults to this URL and will work out of the box.

#### Option 2: Use Your Own Keycloak Instance

If you have Keycloak running elsewhere, create a `.env` file:

```bash
# .env file
KEYCLOAK_URL=http://your-keycloak:8080
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin
REALM_NAME=github-demo
```

#### Option 3: Run Keycloak via Docker

```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Then create a `.env` file with `KEYCLOAK_URL=http://localhost:8080` and other required variables.

### System Requirements

- Python 3.11+
- `curl` and `jq` (for the demo script)
- `uv` (optional, for Python package management) or `pip`

## Quick Start

```bash
cd keycloak_rbac_demo

# 1. Create .env file with your Keycloak settings
cat > .env << EOF
KEYCLOAK_URL=http://keycloak.localtest.me:8080
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin
REALM_NAME=github-demo
EOF

# 2. Install dependencies
pip install -r requirements.txt
# Or with uv:
# uv venv && source .venv/bin/activate && uv pip install -r requirements.txt

# 3. Set up the realm (creates github-demo realm with all resources)
python setup_demo.py config.yaml scope_configs.yaml

# 4. Run the demo (shows token exchanges for 3 users)
./run_github_demo.sh

# 5. Clean up (deletes the github-demo realm)
./cleanup.sh
```

## What Gets Created

The [`setup_demo.py`](setup_demo.py) script creates a complete realm (default: `github-demo`) with:

### Clients (all confidential, token exchange enabled)
- `demo-ui` - Entry point for user login
- `github-agent` - First-stage agent service
- `github-tool-partial` - Second-stage partial tool access
- `github-tool-full` - Second-stage full tool access

### Realm Roles
- `github-agent-access` - Required to exchange for github-agent token
- `github-tool-partial-access` - Required to exchange for github-tool-partial token
- `github-tool-full-access` - Required to exchange for github-tool-full token

### Client Scopes (with audience mappers)
- `github-agent-audience` → adds `github-agent` to audience (gated by `github-agent-access` role)
- `github-tool-partial-audience` → adds `github-tool-partial` to audience (gated by `github-tool-partial-access` role)
- `github-tool-full-audience` → adds `github-tool-full` to audience (gated by `github-tool-full-access` role)

### Users
- alice, bob, charlie (each with different role assignments, all with password='password')

## How It Works

### Role-Based Audience Inclusion

1. **Client scopes** define audience mappers that add specific clients to the `aud` claim
2. **Realm roles** are assigned to these client scopes via scope-mappings
3. Only users with the required role get the audience claim in their token
4. Token exchange requires the target client to be in the subject token's audience

### Token Exchange Flow Example (Alice's Path)

1. **Login:** Alice authenticates via `demo-ui` → receives token with `aud: [github-agent]` (she has `github-agent-access`)
2. **Stage 1:** Exchange for `github-agent` token → ✅ succeeds (audience matches)
3. **New token** includes `aud: [github-tool-partial, github-tool-full]` (she has both tool access roles)
4. **Stage 2:** Exchange for `github-tool-partial` token → ✅ succeeds (audience matches)
5. **Stage 3:** Exchange for `github-tool-full` token → ✅ succeeds (audience matches)

When Bob tries to access full tool:
1. **Login:** Token includes `aud: [github-agent]` (he has `github-agent-access`)
2. **Stage 1:** Exchange for `github-agent` → ✅ succeeds
3. **New token** includes `aud: [github-tool-partial]` but NOT `github-tool-full` (missing `github-tool-full-access` role)
4. **Stage 2:** Exchange for `github-tool-partial` → ✅ succeeds
5. **Stage 3:** Exchange for `github-tool-full` → ❌ fails with "Requested audience not available"

## Demo Output

The [`run_github_demo.sh`](run_github_demo.sh) script provides:
- Color-coded PASS/FAIL for each exchange
- JWT claim inspection showing audience and roles
- Summary table comparing actual vs. expected results
- Clear error messages explaining why exchanges fail

## Key Takeaways

1. **Audience-based gating**: Token exchange requires the subject token to
   contain the target client as an audience claim.
2. **Role-scoped audiences**: Audience mappers are tied to client scopes
   which require specific realm roles. No role = no audience = no exchange.
3. **Defense in depth**: Even if a user can reach Stage 1 of a path, they
   still need the correct role for Stage 2 — each hop is independently gated.
4. **Least privilege**: Users only get the tokens they need for the services
   they're authorized to access.

## Configuration Files

The demo uses three configuration files:

### `.env` - Environment Variables
Contains Keycloak connection settings and realm name:
```bash
KEYCLOAK_URL=http://keycloak.localtest.me:8080
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin
REALM_NAME=github-demo
```

### `config.yaml` - Main Configuration
Defines clients, roles, users, and client scope assignments. See [`config.yaml`](config.yaml) for the complete structure.

### `scope_configs.yaml` - Access Control Policy
Maps client scopes to required roles for audience inclusion. Each scope can have one or more roles assigned. Users with ANY of the assigned roles will get the corresponding audience claim in their tokens.

Example structure:
```yaml
policy:
  github-agent-audience:
    - github-agent-access
    - admin-access              # Users with either role get the audience
  github-tool-partial-audience:
    - github-tool-partial-access
  github-tool-full-audience:
    - github-tool-full-access
```

See [`scope_configs.yaml`](scope_configs.yaml) for the complete configuration.

## Additional Scripts

- [`apply_policy.sh`](apply_policy.sh) - Apply access control policy to existing realm
- [`cleanup_policy.sh`](cleanup_policy.sh) - Remove access control policy from realm
- [`delete_access_control_policy.py`](delete_access_control_policy.py) - Python script to delete policy
- [`apply_access_control_policy.py`](apply_access_control_policy.py) - Python script to apply policy

## Troubleshooting

**"Account is not fully set up" error:**
- This demo creates users with credentials embedded in the user creation payload
- Ensure you're running the latest setup script

**Token exchange fails with "Public client not allowed":**
- All clients in this demo are confidential (with secrets)
- Verify `serviceAccountsEnabled: true` is set for all clients

**"Requested audience not available":**
- This is expected behavior! It means the user lacks the required role
- Check the user's role assignments in Keycloak admin console

**Missing environment variables:**
- Ensure your `.env` file contains all required variables: `KEYCLOAK_URL`, `KEYCLOAK_ADMIN_USERNAME`, `KEYCLOAK_ADMIN_PASSWORD`, `REALM_NAME`

## Viewing in Keycloak Admin Console

After running [`setup_demo.py`](setup_demo.py), you can inspect the configuration:

```
http://keycloak.localtest.me:8080/admin/master/console/#/github-demo
```

Navigate to:
- **Clients** → See the 4 clients and their token exchange settings
- **Realm roles** → See the 3 access control roles
- **Client scopes** → See audience mappers and role assignments
- **Users** → See alice/bob/charlie and their role assignments

## Related Resources

- [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange) - Official Keycloak documentation
- [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) - IETF RFC 8693
- [spire-demos/keycloak_token_exchange](../keycloak_token_exchange/) - SPIRE-based token exchange demo
