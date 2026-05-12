#!/bin/sh
set -e

container_name="lualdap-nginx-test"
ldap_image="bitnamilegacy/openldap:latest"
ldap_port="${LDAP_PORT:-1389}"

# LDAP connection configuration
base_dn="dc=example,dc=org"
bind_dn="cn=manager,${base_dn}"
password="password"

# Verbosity
verbose=0

# Parse flags
while [ $# -gt 0 ]; do
  case "$1" in
    -v)
      verbose=1
      shift
      ;;
    start|stop|restart|status|shell)
      cmd="$1"
      shift
      ;;
    *)
      echo "Usage: $0 [-v] {start|stop|restart|status|shell}"
      exit 1
      ;;
  esac
done

[ -z "$cmd" ] && { echo "No command provided. Usage: $0 [-v] {start|stop|restart|status|shell}"; exit 1; }

debug() {
  if [ "$verbose" -eq 1 ]; then
    echo "$@"
  fi
}

start_container() {
  existing_image=$(docker inspect --format '{{.Config.Image}}' "$container_name" 2>/dev/null || true)
  if [ -z "$existing_image" ]; then
    debug "Starting container '$container_name' with image '$ldap_image'"
    docker run -d --name "$container_name" \
      -p "${ldap_port}:1389" \
      -e LDAP_ROOT="${base_dn}" \
      -e LDAP_ADMIN_USERNAME=manager \
      -e LDAP_ADMIN_PASSWORD="${password}" \
      -e LDAP_USERS=testuser \
      -e LDAP_PASSWORDS=testpass \
      -e LDAP_ENABLE_SYNCPROV=true \
      "$ldap_image"
  elif [ "$existing_image" != "$ldap_image" ]; then
    echo "Container '$container_name' exists with image '$existing_image'; replacing with '$ldap_image'"
    docker rm -f "$container_name"
    start_container
    return
  else
    debug "Container '$container_name' already exists with correct image"
  fi

  echo "Waiting for LDAP to become available..."
  while ! ldapsearch -H "ldap://127.0.0.1:${ldap_port}" \
      -D "${bind_dn}" -w "${password}" \
      -b "${base_dn}" -s base > /dev/null 2>&1; do
    sleep 1
  done
  echo "LDAP is available"

  # Grant cn=testuser write access to the test base. Required by the
  # proxy_id tests, which bind as manager and use proxy authz to perform
  # writes as testuser; the differential success/failure (and the recorded
  # creatorsName/modifiersName) is the proof that proxy_id is being applied
  # by the server. Without this ACL the bitnami default would refuse the
  # writes and the tests couldn't tell a wired-up proxy from a broken one.
  docker exec -i "$container_name" ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<EOF
dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to dn.subtree="${base_dn}" by dn="cn=testuser,ou=users,${base_dn}" write by * read
EOF
}

stop_container() {
  if docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
    debug "Stopping and removing container '$container_name'"
    docker rm -f "$container_name" > /dev/null
  else
    debug "Container '$container_name' is not running"
  fi
}

status_container() {
  if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
    echo "Container '$container_name' is running"
  else
    echo "Container '$container_name' is not running"
    exit 1
  fi
}

shell_container() {
  docker exec -it ${container_name} /bin/bash
}

case "$cmd" in
  start)
    start_container
    ;;
  stop)
    stop_container
    ;;
  restart)
    stop_container
    start_container
    ;;
  status)
    status_container
    ;;
  shell)
    shell_container
    ;;
esac
