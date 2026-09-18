# Expose various LuaLDAP-nginx functions as HTTP endpoints to allow testing

## ldap-pooled

The `ldap-pooled` endpoint copies dapman's connection lifecycle: a pooled
cosocket, a connection object cached by fd, and no `conn:close()`. The `mode`
argument accepts `pool`, `drop`, or `gc`. The endpoint exists to reproduce the
connection finalizer writing an UNBIND PDU through a freed `ngx_connection_t`.
See `tests/pooled_gc.lua`.
