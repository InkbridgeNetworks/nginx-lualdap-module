#!/bin/sh
#
# Top-level test harness for lualdap-nginx-module.
#
# Starts the bitnami OpenLDAP container (syncprov enabled) and nginx,
# discovers every tests/*_test.lua file, runs each one in order, then
# tears everything down and prints a summary.
#
# Usage:
#   ./run-tests.sh [-k] [-v] [-p] [extra lua args...]
#
#   -k   keep containers/nginx running after tests finish
#   -v   verbose nginx (logs to stderr instead of file)
#   -p   pass --parallel to the Lua runner (classes run in parallel)
#   Additional arguments are forwarded verbatim to every Lua test file.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEEP=0
VERBOSE=0
LUA_EXTRA=""
LUA54="${LUA54:-/opt/homebrew/opt/lua@5.4/bin/lua5.4}"

# Parse flags we own; accumulate the rest for Lua.
while [ $# -gt 0 ]; do
    case "$1" in
        -k) KEEP=1; shift ;;
        -v) VERBOSE=1; shift ;;
        -p|--parallel) LUA_EXTRA="$LUA_EXTRA --parallel"; shift ;;
        *) LUA_EXTRA="$LUA_EXTRA $1"; shift ;;
    esac
done

# Connection defaults (tests inherit these via env).
export NGINX_HOST="${NGINX_HOST:-127.0.0.1}"
export NGINX_PORT="${NGINX_PORT:-8090}"
export TEST_PORT="$NGINX_PORT"
export LDAP_HOST="${LDAP_HOST:-127.0.0.1}"
export LDAP_PORT="${LDAP_PORT:-1389}"
export LDAP_BASE="${LDAP_BASE:-dc=example,dc=org}"
export LDAP_BIND="${LDAP_BIND:-cn=manager,dc=example,dc=org}"
export LDAP_PASS="${LDAP_PASS:-password}"

# ---------------------------------------------------------------------------
# Infrastructure lifecycle
# ---------------------------------------------------------------------------

cleanup() {
    rc=$?
    echo ""
    if [ "$KEEP" -eq 1 ]; then
        echo "Leaving LDAP container and nginx running (-k)."
    else
        printf "Stopping nginx... "
        "$SCRIPT_DIR/nginx-service.sh" stop 2>/dev/null && echo "done" || echo "skipped"
        printf "Stopping LDAP container... "
        "$SCRIPT_DIR/ldap-container.sh" stop 2>/dev/null && echo "done" || echo "skipped"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

start_infrastructure() {
    echo "Starting LDAP container..."
    "$SCRIPT_DIR/ldap-container.sh" start

    echo "Starting nginx..."
    if [ "$VERBOSE" -eq 1 ]; then
        "$SCRIPT_DIR/nginx-service.sh" start fg &
    else
        "$SCRIPT_DIR/nginx-service.sh" start bg
    fi

    printf "Waiting for nginx on %s:%s" "$NGINX_HOST" "$NGINX_PORT"
    i=0
    while [ "$i" -lt 40 ]; do
        if nc -z "$NGINX_HOST" "$NGINX_PORT" 2>/dev/null; then
            echo "  ready"
            return 0
        fi
        printf "."
        sleep 0.5
        i=$((i + 1))
    done
    echo ""
    echo "ERROR: nginx did not become ready in time." >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

start_infrastructure

# shellcheck disable=SC2086
cd "$SCRIPT_DIR" && "$LUA54" bin/run_tests $LUA_EXTRA
exit "$?"
