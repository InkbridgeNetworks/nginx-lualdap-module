#!/bin/sh
# Run SSE integration tests.
#
# Starts the bitnami OpenLDAP container (syncprov enabled) and nginx,
# runs the LuaUnit suite, then tears everything down.
#
# Usage:
#   ./tests/run-sse-tests.sh [-k] [-v]
#
#   -k  keep containers/nginx running after tests (useful for manual inspection)
#   -v  verbose nginx (foreground with debug output)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KEEP=0
VERBOSE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -k) KEEP=1;   shift ;;
        -v) VERBOSE=1; shift ;;
        *)  echo "Usage: $0 [-k] [-v]"; exit 1 ;;
    esac
done

export NGINX_HOST="${NGINX_HOST:-127.0.0.1}"
export NGINX_PORT="${NGINX_PORT:-8080}"
export LDAP_HOST="${LDAP_HOST:-127.0.0.1}"
export LDAP_PORT="${LDAP_PORT:-389}"
export LDAP_BASE="${LDAP_BASE:-dc=example,dc=org}"
export LDAP_BIND="${LDAP_BIND:-cn=manager,dc=example,dc=org}"
export LDAP_PASS="${LDAP_PASS:-password}"

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "Leaving LDAP container and nginx running (-k)"
        return
    fi
    echo "Stopping nginx..."
    "$SCRIPT_DIR/nginx-service.sh" stop 2>/dev/null || true
    echo "Stopping LDAP container..."
    "$SCRIPT_DIR/ldap-container.sh" stop 2>/dev/null || true
}
trap cleanup EXIT

# Start LDAP container
echo "Starting LDAP container..."
"$SCRIPT_DIR/ldap-container.sh" start

# Start nginx
echo "Starting nginx..."
if [ "$VERBOSE" -eq 1 ]; then
    "$SCRIPT_DIR/nginx-service.sh" start bg
else
    "$SCRIPT_DIR/nginx-service.sh" start bg
fi

# Wait for nginx
echo "Waiting for nginx on ${NGINX_HOST}:${NGINX_PORT}..."
for i in $(seq 1 20); do
    if nc -z "$NGINX_HOST" "$NGINX_PORT" 2>/dev/null; then
        echo "nginx ready"
        break
    fi
    sleep 0.5
    if [ "$i" -eq 20 ]; then
        echo "nginx did not start in time" >&2
        exit 1
    fi
done

echo ""
echo "Running SSE tests..."
echo "--------------------"
exec ${LUA:-lua5.1} "$SCRIPT_DIR/tests/sse_test.lua" "$@"
