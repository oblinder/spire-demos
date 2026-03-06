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
# Configuration
# ---------------------------------------------------------------------------
KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak.localtest.me:8080}"
REALM="rbac-demo"
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
        RESULTS[$((user_idx * 4 + 0))]="FAIL"  # alpha_s1
        RESULTS[$((user_idx * 4 + 1))]="-"     # alpha_s2
        RESULTS[$((user_idx * 4 + 2))]="FAIL"  # beta_s1
        RESULTS[$((user_idx * 4 + 3))]="-"     # beta_s2
        return 0
    fi
    echo ""
    show_claims "$user_token" "initial (demo-ui)"
    echo ""

    # --- Alpha path ---
    echo -e "  ${BOLD}Alpha Path: demo-ui -> app-alpha -> backend-alpha${RESET}"
    echo ""

    # Stage 1: demo-ui -> app-alpha
    echo -e "  ${BOLD}Stage 1: demo-ui -> app-alpha${RESET}"
    local app_alpha_token
    app_alpha_token=$(token_exchange "$user_token" "app-alpha" "demo-ui" "demo-ui-secret")
    if [[ $? -eq 0 && -n "$app_alpha_token" ]]; then
        RESULTS[$((user_idx * 4 + 0))]="PASS"

        # Stage 2: app-alpha -> backend-alpha
        echo ""
        echo -e "  ${BOLD}Stage 2: app-alpha -> backend-alpha${RESET}"
        local backend_alpha_token
        backend_alpha_token=$(token_exchange "$app_alpha_token" "backend-alpha" "app-alpha" "app-alpha-secret")
        if [[ $? -eq 0 && -n "$backend_alpha_token" ]]; then
            RESULTS[$((user_idx * 4 + 1))]="PASS"
        else
            RESULTS[$((user_idx * 4 + 1))]="FAIL"
        fi
    else
        RESULTS[$((user_idx * 4 + 0))]="FAIL"
        RESULTS[$((user_idx * 4 + 1))]="-"
    fi

    echo ""

    # --- Beta path ---
    echo -e "  ${BOLD}Beta Path: demo-ui -> app-beta -> backend-beta${RESET}"
    echo ""

    # Stage 1: demo-ui -> app-beta
    echo -e "  ${BOLD}Stage 1: demo-ui -> app-beta${RESET}"
    local app_beta_token
    app_beta_token=$(token_exchange "$user_token" "app-beta" "demo-ui" "demo-ui-secret")
    if [[ $? -eq 0 && -n "$app_beta_token" ]]; then
        RESULTS[$((user_idx * 4 + 2))]="PASS"

        # Stage 2: app-beta -> backend-beta
        echo ""
        echo -e "  ${BOLD}Stage 2: app-beta -> backend-beta${RESET}"
        local backend_beta_token
        backend_beta_token=$(token_exchange "$app_beta_token" "backend-beta" "app-beta" "app-beta-secret")
        if [[ $? -eq 0 && -n "$backend_beta_token" ]]; then
            RESULTS[$((user_idx * 4 + 3))]="PASS"
        else
            RESULTS[$((user_idx * 4 + 3))]="FAIL"
        fi
    else
        RESULTS[$((user_idx * 4 + 2))]="FAIL"
        RESULTS[$((user_idx * 4 + 3))]="-"
    fi
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
print_summary() {
    echo -e "${BOLD}${CYAN}Summary${RESET}"
    echo ""
    printf "  %-10s %-12s %-12s %-12s %-12s\n" "User" "Alpha S1" "Alpha S2" "Beta S1" "Beta S2"
    printf "  %-10s %-12s %-12s %-12s %-12s\n" "────────" "──────────" "──────────" "──────────" "──────────"

    local users=(alice bob charlie)
    local user_idx=0
    for username in "${users[@]}"; do
        local a1="${RESULTS[$((user_idx * 4 + 0))]:-?}"
        local a2="${RESULTS[$((user_idx * 4 + 1))]:-?}"
        local b1="${RESULTS[$((user_idx * 4 + 2))]:-?}"
        local b2="${RESULTS[$((user_idx * 4 + 3))]:-?}"

        # Colorize
        [[ "$a1" == "PASS" ]] && a1="${GREEN}PASS${RESET}" || a1="${RED}${a1}${RESET}"
        [[ "$a2" == "PASS" ]] && a2="${GREEN}PASS${RESET}" || a2="${RED}${a2}${RESET}"
        [[ "$b1" == "PASS" ]] && b1="${GREEN}PASS${RESET}" || b1="${RED}${b1}${RESET}"
        [[ "$b2" == "PASS" ]] && b2="${GREEN}PASS${RESET}" || b2="${RED}${b2}${RESET}"

        printf "  %-10s %-21s %-21s %-21s %-21s\n" "$username" "$a1" "$a2" "$b1" "$b2"
        ((user_idx++))
    done

    echo ""
    echo -e "${BOLD}Expected results:${RESET}"
    echo "  Alice:   PASS  PASS  FAIL  -     (has alpha-access + backend-alpha-access, missing app-beta-access)"
    echo "  Bob:     PASS  FAIL  PASS  PASS  (has app-alpha-access but missing backend-alpha-access)"
    echo "  Charlie: FAIL  -     FAIL  -     (no roles at all)"
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
    echo "║         Keycloak RBAC Token Exchange Demo               ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "Keycloak: ${KEYCLOAK_URL}"
    echo -e "Realm:    ${REALM}"
    echo ""

    local users=(alice bob charlie)
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
