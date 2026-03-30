#!/bin/bash
# =============================================================================
# Keycloak RBAC Token Exchange Demo
#
# Demonstrates a 2-stage token exchange chain with role-based gating.
# Requires: curl, jq, and a running Keycloak with the rbac-demo realm.
#
# Usage: ./run_demo.sh
# =============================================================================
set -o pipefail

# ---------------------------------------------------------------------------
# Load environment variables from .env file
# ---------------------------------------------------------------------------
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak.localtest.me:9090}"
REALM="${REALM_NAME:-github-demo}"
TOKEN_URL="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Results tracking (using simple variables for bash 3 compatibility)
# ---------------------------------------------------------------------------
# We'll use simple indexed arrays and track results per user

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
check_deps() {
    for cmd in curl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}ERROR: '$cmd' is required but not installed.${RESET}"
            exit 1
        fi
    done
}

decode_jwt() {
    local token="$1"
    # Use Python for cross-platform JWT decoding
    python3 -c "
import sys, json, base64
token = sys.argv[1]
payload = token.split('.')[1]
# Add padding
padding = 4 - len(payload) % 4
if padding != 4:
    payload += '=' * padding
try:
    claims = json.loads(base64.urlsafe_b64decode(payload))
    print(json.dumps(claims))
except Exception as e:
    print('{\"error\": \"decode failed\"}')
" "$token" 2>/dev/null
}

show_claims() {
    local token="$1"
    local label="$2"
    local claims
    claims=$(decode_jwt "$token")
    echo -e "${DIM}  Claims for ${label}:${RESET}" >&2
    # Show sub, aud, and realm_access if present
    echo "$claims" | jq -r '{
        sub,
        aud,
        realm_access: (if .realm_access then .realm_access.roles else null end)
    }' 2>/dev/null | sed 's/^/    /' >&2
}

login_user() {
    local username="$1"

    # Show the curl command (what the user does)
    echo -e "${DIM}  curl -X POST \$TOKEN_URL \\" >&2
    echo -e "    -d \"grant_type=password\" \\" >&2
    echo -e "    -d \"client_id=demo-ui\" \\" >&2
    echo -e "    -d \"client_secret=demo-ui-secret\" \\" >&2
    echo -e "    -d \"username=${username}\" \\" >&2
    echo -e "    -d \"password=password\"${RESET}" >&2
    echo "" >&2

    local response
    response=$(curl -s -X POST "$TOKEN_URL" \
        -d "grant_type=password" \
        -d "client_id=demo-ui" \
        -d "client_secret=demo-ui-secret" \
        -d "username=${username}" \
        -d "password=password")

    local token
    token=$(echo "$response" | jq -r '.access_token // empty')
    if [[ -z "$token" ]]; then
        echo -e "  ${RED}Login FAILED${RESET}" >&2
        echo "$response" | jq -r '.error_description // .error // "unknown error"' | sed 's/^/    /' >&2
        return 1
    fi
    echo -e "${CYAN}  Parsed JWT Claims:${RESET}" >&2
    decode_jwt "$token" | jq '.' 2>/dev/null | sed 's/^/    /' >&2
    echo "" >&2
    echo -e "  ${GREEN}Login OK${RESET}" >&2
    echo "$token"  # Output token to stdout for capture
    return 0
}

token_exchange() {
    local subject_token="$1"
    local target_client="$2"
    local source_client="$3"
    local source_secret="$4"

    # Show the curl command (what the user does - same for all users!)
    echo -e "${DIM}  curl -X POST \$TOKEN_URL \\" >&2
    echo -e "    -d \"grant_type=urn:ietf:params:oauth:grant-type:token-exchange\" \\" >&2
    echo -e "    -d \"subject_token=\$TOKEN\" \\" >&2
    echo -e "    -d \"subject_token_type=urn:ietf:params:oauth:token-type:access_token\" \\" >&2
    echo -e "    -d \"requested_token_type=urn:ietf:params:oauth:token-type:access_token\" \\" >&2
    echo -e "    -d \"client_id=${source_client}\" \\" >&2
    echo -e "    -d \"client_secret=${source_secret}\" \\" >&2
    echo -e "    -d \"audience=${target_client}\"${RESET}" >&2
    echo "" >&2

    local response
    # All clients are now confidential
    response=$(curl -s -X POST "$TOKEN_URL" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "subject_token=${subject_token}" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "client_id=${source_client}" \
        -d "client_secret=${source_secret}" \
        -d "audience=${target_client}")

    local token
    token=$(echo "$response" | jq -r '.access_token // empty')
    if [[ -z "$token" ]]; then
        local error
        error=$(echo "$response" | jq -r '.error_description // .error // "unknown error"')
        echo -e "  ${RED}FAIL${RESET} - Exchange ${source_client} -> ${target_client}" >&2
        echo -e "    ${DIM}${error}${RESET}" >&2
        echo "" >&2
        return 1
    fi
    echo -e "  ${GREEN}PASS${RESET} - Exchange ${source_client} -> ${target_client}" >&2
    show_claims "$token" "$target_client"
    echo "" >&2
    echo "$token"  # Output token to stdout for capture
    return 0
}

separator() {
    echo -e "\n${CYAN}$(printf '%.0s─' {1..60})${RESET}\n"
}

# ---------------------------------------------------------------------------
# Verify resource roles in token for target client
# ---------------------------------------------------------------------------
verify_target_resource_roles() {
    local token="$1"
    local target_client="$2"
    local target_role="$3"
    local target_scope="$4"

    local claims
    claims=$(decode_jwt "$token")
    
    # Extract resource_access roles for the target client
    local roles
    roles=$(echo "$claims" | jq -r ".resource_access.\"${target_client}\".roles // []" 2>/dev/null)
    
    if [[ "$roles" == "[]" || -z "$roles" ]]; then
        echo -e "  ${RED}✗ No resource roles found for ${target_client}${RESET}" >&2
        return 1
    fi
    
    # Display all roles for the target client
    echo -e "  ${GREEN}✓ Resource roles found for ${target_client}:${RESET}" >&2
    echo "$roles" | jq -r '.[]' 2>/dev/null | sed 's/^/    - /' >&2
    
    # Verify the specific target role is present
    if [[ -n "$target_role" ]]; then
        local role_found
        role_found=$(echo "$roles" | jq -r --arg role "$target_role" 'any(.[]; . == $role)' 2>/dev/null)
        
        if [[ "$role_found" == "true" ]]; then
            echo -e "  ${GREEN}✓ Required role '${target_role}' verified${RESET}" >&2
        else
            echo -e "  ${RED}✗ Required role '${target_role}' not found${RESET}" >&2
            return 1
        fi
    fi
    
    # Verify the specific target scope is present
    if [[ -n "$target_scope" ]]; then
        local scope_claim
        scope_claim=$(echo "$claims" | jq -r '.scope // ""' 2>/dev/null)
        
        if [[ -z "$scope_claim" ]]; then
            echo -e "  ${RED}✗ No scope claim found in token${RESET}" >&2
            return 1
        fi
        
        # Check if target_scope is present in the space-separated scope string
        if echo "$scope_claim" | grep -qw "$target_scope"; then
            echo -e "  ${GREEN}✓ Required scope '${target_scope}' verified${RESET}" >&2
        else
            echo -e "  ${RED}✗ Required scope '${target_scope}' not found${RESET}" >&2
            echo -e "    ${DIM}Available scopes: ${scope_claim}${RESET}" >&2
            return 1
        fi
    fi
    
    return 0
}

# ---------------------------------------------------------------------------
# Display JWT token and its claims
# ---------------------------------------------------------------------------
token_display() {
    local token="$1"
    
    echo -e "${CYAN}  Parsed JWT Claims:${RESET}" >&2
    decode_jwt "$token" | jq '.' 2>/dev/null | sed 's/^/    /' >&2
    echo "" >&2
}

# ---------------------------------------------------------------------------
# Run demo for one user
# ---------------------------------------------------------------------------
run_user_demo() {
    local username="$1"
    local user_idx="$2"  # 0=alice, 1=bob, 2=charlie
    echo -e "${BOLD}${YELLOW}▶ User: ${username}${RESET}"
    echo ""

    # Login
    echo -e "  ${BOLD}Step 0: Login via demo-ui${RESET}"
    echo ""
    local user_token
    user_token=$(login_user "$username")
    if [[ $? -ne 0 || -z "$user_token" ]]; then
        # Store results in indexed arrays: [user_idx * 3 + stage_idx]
        RESULTS[$((user_idx * 3 + 0))]="FAIL"  # agent
        RESULTS[$((user_idx * 3 + 1))]="FAIL"  # github-tool:source
        RESULTS[$((user_idx * 3 + 2))]="FAIL"  # github-tool:issues
        return 0
    fi
    echo ""
    show_claims "$user_token" "initial (demo-ui)"
    echo ""

    echo -e "  ${BOLD}demo-ui -> github-agent -> github-tool${RESET}"
    echo ""

    # Stage 1: demo-ui -> github-agent
    echo -e "  ${BOLD}Stage 1: demo-ui -> github-agent${RESET}"
    local agent_token
    agent_token=$(token_exchange "$user_token" "github-agent" "demo-ui" "demo-ui-secret")
    if [[ $? -eq 0 && -n "$agent_token" ]]; then
        token_display "$agent_token"
        if verify_target_resource_roles "$agent_token" "github-agent" "github-agent"; then
            RESULTS[$((user_idx * 3 + 0))]="PASS"
        fi

        # Stage 2: github-agent -> github-tool
        echo ""
        echo -e "  ${BOLD}Stage 2: github-agent -> github-tool${RESET}"
        local github_tool_token
        github_tool_token=$(token_exchange "$agent_token" "github-tool" "github-agent" "github-agent-secret")
        if [[ $? -eq 0 && -n "$github_tool_token" ]]; then
            token_display "$github_tool_token"

            if verify_target_resource_roles "$github_tool_token" "github-tool" "github-partial-access" "github-partial-access"; then
                RESULTS[$((user_idx * 3 + 1))]="PASS"
            else
                echo -e "  ${YELLOW}⚠ Token exchange succeeded but resource role verification failed${RESET}" >&2
                RESULTS[$((user_idx * 3 + 1))]="FAIL"
            fi

            if verify_target_resource_roles "$github_tool_token" "github-tool" "github-full-access" "github-full-access"; then
                RESULTS[$((user_idx * 3 + 2))]="PASS"
            else
                echo -e "  ${YELLOW}⚠ Token exchange succeeded but resource role verification failed${RESET}" >&2
                RESULTS[$((user_idx * 3 + 2))]="FAIL"
            fi
        else
            RESULTS[$((user_idx * 3 + 1))]="FAIL"
        fi
    else
        RESULTS[$((user_idx * 3 + 0))]="FAIL"
        RESULTS[$((user_idx * 3 + 1))]="-"
        RESULTS[$((user_idx * 3 + 2))]="-"
    fi

    echo ""

}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
print_summary() {
    echo -e "${BOLD}${CYAN}Summary${RESET}"
    echo ""
    printf "  %-10s %-9s %-10s %-10s\n" "User" "Agent" "Tool:part" "Tool:full"
    printf "  %-10s %-12s %-12s %-12s\n" "────────" "──────────" "──────────" "──────────"

    local users=(alice bob charlie)
    local user_idx=0
    for username in "${users[@]}"; do
        local agent="${RESULTS[$((user_idx * 3 + 0))]:-?}"
        local gt_iss="${RESULTS[$((user_idx * 3 + 1))]:-?}"
        local gt_src="${RESULTS[$((user_idx * 3 + 2))]:-?}"

        # Format username with printf for alignment
        printf "  %-10s " "$username"

        # Print colored results (each is 4 chars, padded manually to 12)
        [[ "$agent" == "PASS" ]] && echo -ne "${GREEN}PASS${RESET}        " || echo -ne "${RED}$(printf "%-4s" "$agent")${RESET}        "
        [[ "$gt_iss" == "PASS" ]] && echo -ne "${GREEN}PASS${RESET}        " || echo -ne "${RED}$(printf "%-4s" "$gt_iss")${RESET}        "
        [[ "$gt_src" == "PASS" ]] && echo -ne "${GREEN}PASS${RESET}        " || echo -ne "${RED}$(printf "%-4s" "$gt_src")${RESET}        "

        ((user_idx++))
        echo ""
    done

    echo ""
    echo -e "${BOLD}Expected results:${RESET}"
    echo "  Alice:   PASS  PASS  PASS  (agent + github-partial-access + github-full-access)"
    echo "  Bob:     PASS  PASS  FAIL  (agent + github-partial-access only)"
    echo "  Charlie: FAIL  FAIL  FAIL  (no roles at all)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    check_deps

    # Initialize results array (9 elements: 3 users * 3 stages each)
    RESULTS=()

    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         Keycloak Github Token Exchange Demo              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "Keycloak: ${KEYCLOAK_URL}"
    echo -e "Realm:    ${REALM}"
    echo ""

    local users=(alice bob charlie)
    # local users=(alice)
    local user_idx=0
    for username in "${users[@]}"; do
        separator
        run_user_demo "$username" "$user_idx"
        ((user_idx++))
    done

    separator
    print_summary
}

main "$@"
