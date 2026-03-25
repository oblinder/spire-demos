#!/bin/bash
# =============================================================================
# Keycloak RBAC Token Exchange Demo
#
# Demonstrates a 2-3 stage token exchange chain with role-based gating.
# Shows how users with different roles can access different levels of the
# github tool (agent, partial, full).
#
# Requires: curl, jq, Python 3, and a running Keycloak with the configured realm.
#
# Usage: ./run_github_demo.sh
#
# Environment variables (from .env file):
#   KEYCLOAK_URL
#   REALM_NAME
# =============================================================================
set -o pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Load environment variables from .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Check required environment variables
if [ -z "$KEYCLOAK_URL" ] || [ -z "$REALM_NAME" ]; then
    echo "ERROR: Missing required environment variables. Please ensure .env file contains:"
    echo "  KEYCLOAK_URL"
    echo "  REALM_NAME"
    exit 1
fi

REALM="$REALM_NAME"
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
        # Store results in indexed arrays: [user_idx * 4 + stage_idx]
        RESULTS[$((user_idx * 4 + 0))]="FAIL"  # agent
        RESULTS[$((user_idx * 4 + 1))]="FAIL"  # tool-p
        RESULTS[$((user_idx * 4 + 2))]="FAIL"  # tool-f
        return 0
    fi
    echo ""
    show_claims "$user_token" "initial (demo-ui)"
    echo ""

    echo -e "  ${BOLD}demo-ui -> github-agent -> github-tool-partial"
    echo -e "                          -> github-tool-full${RESET}"
    echo ""

    # Stage 1: demo-ui -> github-agent
    echo -e "  ${BOLD}Stage 1: demo-ui -> github-agent${RESET}"
    local agent_token
    agent_token=$(token_exchange "$user_token" "github-agent" "demo-ui" "demo-ui-secret")
    if [[ $? -eq 0 && -n "$agent_token" ]]; then
        RESULTS[$((user_idx * 4 + 0))]="PASS"

        # Stage 2: github-agent -> github-tool-partial
        echo ""
        echo -e "  ${BOLD}Stage 2: github-agent -> github-tool-partial${RESET}"
        local tool_token
        tool_token=$(token_exchange "$agent_token" "github-tool-partial" "github-agent" "github-agent-secret")
        if [[ $? -eq 0 && -n "$tool_token" ]]; then
            RESULTS[$((user_idx * 4 + 1))]="PASS"
        else
            RESULTS[$((user_idx * 4 + 1))]="FAIL"
        fi

        # Stage 3: github-agent -> github-tool-full
        echo ""
        echo -e "  ${BOLD}Stage 3: github-agent -> github-tool-full${RESET}"
        local tool_token
        tool_token=$(token_exchange "$agent_token" "github-tool-full" "github-agent" "github-agent-secret")
        if [[ $? -eq 0 && -n "$tool_token" ]]; then
            RESULTS[$((user_idx * 4 + 2))]="PASS"
        else
            RESULTS[$((user_idx * 4 + 2))]="FAIL"
        fi
    else
        RESULTS[$((user_idx * 4 + 0))]="FAIL"
        RESULTS[$((user_idx * 4 + 1))]="-"
        RESULTS[$((user_idx * 4 + 2))]="-"
    fi

    echo ""

}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
print_summary() {
    echo -e "${BOLD}${CYAN}Summary${RESET}"
    echo ""
    printf "  %-10s %-10s %-10s %-12s %-12s\n" "User" "Agent" "Tool P" "Tool F"
    printf "  %-10s %-12s %-12s %-12s %-12s\n" "────────" "──────────" "──────────" "──────────"

    local users=(alice bob charlie)
    local user_idx=0
    for username in "${users[@]}"; do
        local agent="${RESULTS[$((user_idx * 4 + 0))]:-?}"
        local tool_p="${RESULTS[$((user_idx * 4 + 1))]:-?}"
        local tool_f="${RESULTS[$((user_idx * 4 + 2))]:-?}"

        # Format username with printf for alignment
        printf "  %-10s " "$username"

        # Print colored results (each is 4 chars, padded manually to 12)
        [[ "$agent" == "PASS" ]] && echo -ne "${GREEN}PASS${RESET}        " || echo -ne "${RED}$(printf "%-4s" "$agent")${RESET}        "
        [[ "$tool_p" == "PASS" ]] && echo -ne "${GREEN}PASS${RESET}        " || echo -ne "${RED}$(printf "%-4s" "$tool_p")${RESET}        "
        [[ "$tool_f" == "PASS" ]] && echo -ne "${GREEN}PASS${RESET}        " || echo -ne "${RED}$(printf "%-4s" "$tool_f")${RESET}        "

        ((user_idx++))
        echo ""
    done

    echo ""
    echo -e "${BOLD}Expected results:${RESET}"
    echo "  Alice:   PASS  PASS  PASS  -  (agent + tool-p + tool-f)"
    echo "  Bob:     PASS  PASS  FAIL  -  (agent + tool-p)"
    echo "  Charlie: FAIL  FAIL  FAIL  -  (no roles at all)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    check_deps

    # Initialize results array (12 elements: 3 users * 4 stages each)
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