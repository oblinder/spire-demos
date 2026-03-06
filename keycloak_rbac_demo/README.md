# Keycloak RBAC Token Exchange Demo

A standalone teaching demo that illustrates Keycloak role-based access control (RBAC) through OAuth2 token exchange. This demo shows how roles gate access at each stage of a multi-hop token exchange chain.

## Overview

This demo creates a self-contained `rbac-demo` realm in Keycloak with a 2-stage token exchange architecture. Users obtain tokens through a chain of exchanges, where each stage requires specific realm roles. Without the required role, the audience claim is not included in the token, causing the exchange to fail.

## Architecture

```
                      ┌─────────────┐     ┌────────────────┐
                 ┌───►│  app-alpha  ├────►│ backend-alpha  │
                 │    └─────────────┘     └────────────────┘
┌────────────┐   │    Stage 1              Stage 2
│  demo-ui   ├───┤    (needs app-alpha-    (needs backend-alpha-
│(confidential)  │     access role)         access role)
└────────────┘   │
  User login     │    ┌─────────────┐     ┌────────────────┐
                 └───►│  app-beta   ├────►│ backend-beta   │
                      └─────────────┘     └────────────────┘
                      Stage 1              Stage 2
                      (needs app-beta-     (needs backend-beta-
                       access role)         access role)
```

**Token exchange flow (2 stages per path):**
- **Stage 1:** User logs in via `demo-ui`, exchanges token for `app-{alpha,beta}`
  (requires `app-{alpha,beta}-access` role for audience inclusion)
- **Stage 2:** Exchange `app-{alpha,beta}` token for `backend-{alpha,beta}`
  (requires `backend-{alpha,beta}-access` role for audience inclusion)

**Role-gating mechanism:** Each client scope has a corresponding realm role
assigned via scope-mappings. The audience claim is only included in the token
if the user has the required role. Without the audience claim, the token
exchange fails because the subject_token won't list the target client as
audience.

## Users and Expected Results

| User    | Roles                                                   |
|---------|---------------------------------------------------------|
| alice   | `app-alpha-access`, `backend-alpha-access`, `backend-beta-access` |
| bob     | `app-alpha-access`, `app-beta-access`, `backend-beta-access`      |
| charlie | *(none)*                                                |

| User    | Alpha S1 | Alpha S2 | Beta S1 | Beta S2 |
|---------|----------|----------|---------|---------|
| alice   | PASS     | PASS     | FAIL    | -       |
| bob     | PASS     | FAIL     | PASS    | PASS    |
| charlie | FAIL     | -        | FAIL    | -       |

**Why:**
- **Alice** can reach `backend-alpha` (has both alpha roles) but can't even
  start the beta path (missing `app-beta-access`).
- **Bob** can start the alpha path but can't reach `backend-alpha` (missing
  `backend-alpha-access`). He can complete the full beta path.
- **Charlie** has no roles so both paths fail at Stage 1.

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

If you have Keycloak running elsewhere, set environment variables:

```bash
export KEYCLOAK_URL="http://your-keycloak:8080"
export KEYCLOAK_ADMIN_USERNAME="admin"
export KEYCLOAK_ADMIN_PASSWORD="admin"
```

#### Option 3: Run Keycloak via Docker

```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Then use the default settings or set `KEYCLOAK_URL=http://localhost:8080`.

### System Requirements

- Python 3.11+
- `curl` and `jq` (for the demo script)
- `uv` (optional, for Python package management) or `pip`

## Quick Start

```bash
cd keycloak_rbac_demo

# 1. Install dependencies
pip install -r requirements.txt
# Or with uv:
# uv venv && source .venv/bin/activate && uv pip install -r requirements.txt

# 2. Set up the realm (creates rbac-demo realm with all resources)
python setup_rbac_demo.py

# 3. Run the demo (shows token exchanges for 3 users)
./run_demo.sh

# 4. Clean up (deletes the rbac-demo realm)
./cleanup.sh
```

## What Gets Created

The `setup_rbac_demo.py` script creates a complete `rbac-demo` realm with:

### Clients (all confidential, token exchange enabled)
- `demo-ui` - Entry point for user login
- `app-alpha` - First-stage alpha service
- `backend-alpha` - Second-stage alpha service
- `app-beta` - First-stage beta service
- `backend-beta` - Second-stage beta service

### Realm Roles
- `app-alpha-access` - Required to exchange for app-alpha token
- `backend-alpha-access` - Required to exchange for backend-alpha token
- `app-beta-access` - Required to exchange for app-beta token
- `backend-beta-access` - Required to exchange for backend-beta token

### Client Scopes (with audience mappers)
- `app-alpha-audience` → adds `app-alpha` to audience (gated by `app-alpha-access` role)
- `backend-alpha-audience` → adds `backend-alpha` to audience (gated by `backend-alpha-access` role)
- `app-beta-audience` → adds `app-beta` to audience (gated by `app-beta-access` role)
- `backend-beta-audience` → adds `backend-beta` to audience (gated by `backend-beta-access` role)

### Users
- alice, bob, charlie (each with different role assignments, all with password='password')

## How It Works

### Role-Based Audience Inclusion

1. **Client scopes** define audience mappers that add specific clients to the `aud` claim
2. **Realm roles** are assigned to these client scopes via scope-mappings
3. Only users with the required role get the audience claim in their token
4. Token exchange requires the target client to be in the subject token's audience

### Token Exchange Flow Example (Alice on Alpha Path)

1. **Login:** Alice authenticates via `demo-ui` → receives token with `aud: [app-alpha]` (she has `app-alpha-access`)
2. **Stage 1:** Exchange for `app-alpha` token → ✅ succeeds (audience matches)
3. **New token** includes `aud: [backend-alpha]` (she has `backend-alpha-access`)
4. **Stage 2:** Exchange for `backend-alpha` token → ✅ succeeds (audience matches)

When Alice tries the beta path:
1. **Login:** Token does NOT include `app-beta` in audience (missing `app-beta-access` role)
2. **Stage 1:** Exchange for `app-beta` → ❌ fails with "Requested audience not available"

## Demo Output

The `run_demo.sh` script provides:
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

## Configuration

Override defaults via environment variables:

```bash
export KEYCLOAK_URL="http://keycloak.localtest.me:8080"
export KEYCLOAK_ADMIN_USERNAME="admin"
export KEYCLOAK_ADMIN_PASSWORD="admin"

python setup_rbac_demo.py
```

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

## Viewing in Keycloak Admin Console

After running `setup_rbac_demo.py`, you can inspect the configuration:

```
http://keycloak.localtest.me:8080/admin/master/console/#/rbac-demo
```

Navigate to:
- **Clients** → See the 5 clients and their token exchange settings
- **Realm roles** → See the 4 access control roles
- **Client scopes** → See audience mappers and role assignments
- **Users** → See alice/bob/charlie and their role assignments

## Related Resources

- [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange) - Official Keycloak documentation
- [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) - IETF RFC 8693
- [spire-demos/keycloak_token_exchange](../keycloak_token_exchange/) - SPIRE-based token exchange demo
