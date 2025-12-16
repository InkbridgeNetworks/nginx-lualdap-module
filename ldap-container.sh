#!/bin/sh
set -e

container_name="subman-openldap"
ldap_image="bitnamilegacy/openldap:latest"

# LDAP connection configuration
base_dn="dc=example,dc=org"
bind_dn="cn=manager,${base_dn}"
config_bind_dn="cn=manager,cn=config"
password="password"

# Command wrappers
ldapsearch="ldapsearch -o ldif-wrap=no -v -D '${bind_dn}' -w '${password}'"
ldapsearch_config="ldapsearch -o ldif-wrap=no -v -D '${config_bind_dn}' -w '${password}' -b 'cn=config'"
ldapadd="ldapadd -v -D ${bind_dn} -w ${password}"
ldapadd_config="ldapadd -v -D ${config_bind_dn} -w ${password}"
ldapmodify_config="ldapmodify -v -D ${config_bind_dn} -w ${password}"

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
      echo "Usage: $0 [-v] {start|stop|restart|status}"
      exit 1
      ;;
  esac
done

[ -z "$cmd" ] && { echo "No command provided. Usage: $0 [-v] {start|stop|restart|status}"; exit 1; }

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
      -p 389:389 \
      -e LDAP_PORT_NUMBER=389 \
      -e LDAP_ROOT="${base_dn}" \
      -e LDAP_ADMIN_USERNAME=manager \
      -e LDAP_ADMIN_PASSWORD="${password}" \
      -e LDAP_CONFIG_ADMIN_ENABLED=yes \
      -e LDAP_CONFIG_ADMIN_USERNAME=manager \
      -e LDAP_CONFIG_ADMIN_PASSWORD="${password}" \
      -e LDAP_USERS=api \
      -e LDAP_PASSWORDS=apipass \
      -e LDAP_ENABLE_SYNCPROV=true \
      -e BITNAMI_DEBUG=true \
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
  while ! eval "$ldapsearch -b '${base_dn}'" > /dev/null 2>&1; do
    sleep 1
  done
  echo "LDAP is available"

  for ldif in $(ls devel/etc/openldap/ldif | sort); do
    debug "Adding ${ldif} -- $ldapmodify_config -f devel/etc/openldap/ldif/${ldif}"
    $ldapmodify_config -f "devel/etc/openldap/ldif/${ldif}"
  done

  for schema in submodules/freeradius-server/doc/schemas/ldap/openldap/*.ldif; do
    eval "$ldapadd_config -f \"$schema\""
  done

  for schema in share/openldap/schema/*.ldif; do
    eval "$ldapadd_config -f \"$schema\""
  done

  eval "$ldapadd -c -f \"share/openldap/base/init.ldif\""
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
