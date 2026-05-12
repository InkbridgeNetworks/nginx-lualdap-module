/*
** LuaLDAP
** See Copyright Notice in license.html
** $Id: lualdap.c,v 1.48 2007/12/14 15:11:22 carregal Exp $
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_lua_socket_tcp.h>
#include <ngx_http_lua_util.h>
#include <ngx_http_lua_uthread.h>

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef WIN32
#include <Winsock2.h>
#else
#include <sys/time.h>
#endif

#ifdef WINLDAP
#include "open2winldap.h"
#else
#define LDAP_DEPRECATED 1
#include "openldap.h"
#endif

#define LUA_COMPAT_GETN 1
#include "lua.h"
#include "lauxlib.h"
#if ! defined (LUA_VERSION_NUM) || LUA_VERSION_NUM < 501
#include "compat-5.1.h"
#endif

#include <ddebug.h>

#ifdef WINLDAPAPI
#define timeval l_timeval
typedef ULONG ldap_int_t;
typedef PCHAR ldap_pchar_t;
#else
typedef int ldap_int_t;
typedef const char * ldap_pchar_t;
#endif

#define LUALDAP_PREFIX "LuaLDAP: "
#define LUALDAP_TABLENAME "lualdap"
#define LUALDAP_CONNECTION_METATABLE "LuaLDAP connection"
#define LUALDAP_SEARCH_METATABLE "LuaLDAP search"

#define LUALDAP_MOD_ADD (LDAP_MOD_ADD | LDAP_MOD_BVALUES)
#define LUALDAP_MOD_DEL (LDAP_MOD_DELETE | LDAP_MOD_BVALUES)
#define LUALDAP_MOD_REP (LDAP_MOD_REPLACE | LDAP_MOD_BVALUES)
#define LUALDAP_NO_OP   0

/* Maximum number of attributes manipulated in an operation */
#ifndef LUALDAP_MAX_ATTRS
#define LUALDAP_MAX_ATTRS 100
#endif

/* Size of buffer of NULL-terminated arrays of pointers to struct values */
#ifndef LUALDAP_ARRAY_VALUES_SIZE
#define LUALDAP_ARRAY_VALUES_SIZE (2 * LUALDAP_MAX_ATTRS)
#endif

/* Maximum number of values structures */
#ifndef LUALDAP_MAX_VALUES
#define LUALDAP_MAX_VALUES (LUALDAP_ARRAY_VALUES_SIZE / 2)
#endif

#define TRUE  1
#define FALSE 0

/** LDAP connection information
 */
typedef struct {
	int					version;   	//!< LDAP version
	LDAP	  				*ld;	  	//!< LDAP handle.
	ngx_peer_connection_t			conn;		//!< NGINX peer connection
	ngx_http_lua_socket_tcp_upstream_t	*u;		//!< NGINX Socket object
	char					*proxy_authz_id;     //!< Cached proxy authz identity bytes (heap-owned). May contain embedded NULs.
	size_t					 proxy_authz_id_len; //!< Length of proxy_authz_id, for binary-safe comparison.
	LDAPControl				*proxy_authz_ctrl;   //!< Prebuilt Proxy Authorisation Control; valid iff proxy_authz_id != NULL.
} conn_data;

typedef enum {
	SEARCH_TYPE_NORMAL = 0,			//!< Standard oneshot search with no server side state.
	SEARCH_TYPE_PERSISTENT,			//!< Persistent search
	SEARCH_TYPE_PAGED,			//!< Paged search
} search_type_t;

/** LDAP search context information
 *
 * Represents either a oneshot search, as persistent search or a paged search.
 */
typedef struct {
	int		conn;			//!< conn_data reference
	int		msgid;			//!< Unique msgId associated with the search.
	struct berval	*cookie;		//!< Cookie for paging or persistent searching
	search_type_t	type;			//!< What type of search this is.
	int		morePages;		//!< More pages are available on server.
	struct berval	*latest_cookie;		//!< Most recent syncCookie seen on this persistent search;
						//!< updated from per-entry Sync State Control and from
						//!< intermediate syncInfoMessages, freed in search_close.
} search_data_t;

/** LDAP attribute modification structure
 */
typedef struct {
	LDAPMod		*attrs[LUALDAP_MAX_ATTRS + 1];
	LDAPMod		mods[LUALDAP_MAX_ATTRS];
	int		ai;
	BerValue	*values[LUALDAP_ARRAY_VALUES_SIZE];
	int		vi;
	BerValue	bvals[LUALDAP_MAX_VALUES];
	int		bi;
} attrs_data;

int luaopen_ngx_lualdap(lua_State *L);
ngx_module_t  ngx_lualdap;

#include "lualdap-ngx.c"

/*
 * RFC 4370 Proxy Authorisation Control OID.
 * Value is a UTF-8 authzId: "dn:<dn>" or "u:<uid>".
 */
#define PROXY_AUTHZ_OID "2.16.840.1.113730.3.4.18"

/*
 * Build or reuse the Proxy Authorisation Control for conn.
 *
 * Returns NULL when authz_id is NULL so callers can pass NULL directly to
 * ldap_*_ext as the server-controls array element.  When authz_id matches
 * the cached id the existing control is returned immediately (zero work).
 * Otherwise the old control is torn down and a new one is built; its memory
 * is freed in ngx_http_auth_ldap_close_connection.
 *
 * authz_id is treated as binary (bv_val + bv_len); it is not assumed to be
 * NUL-terminated.  ldap_control_create dups the value internally.
 */
static LDAPControl *
proxy_control_add(conn_data *conn, const struct berval *authz_id)
{
	int rc;

	if (!authz_id || !authz_id->bv_val)
		return NULL;

	/* Cache hit: same authz_id bytes as last call, reuse the prebuilt control. */
	if (conn->proxy_authz_id
	    && conn->proxy_authz_id_len == authz_id->bv_len
	    && memcmp(conn->proxy_authz_id, authz_id->bv_val, authz_id->bv_len) == 0)
		return conn->proxy_authz_ctrl;

	/* Cache miss: tear down any stale control and rebuild. */
	if (conn->proxy_authz_ctrl) {
		ldap_control_free(conn->proxy_authz_ctrl);
		conn->proxy_authz_ctrl = NULL;
	}
	free(conn->proxy_authz_id);
	conn->proxy_authz_id = NULL;
	conn->proxy_authz_id_len = 0;

	rc = ldap_control_create((char *)PROXY_AUTHZ_OID, 1,
				 (struct berval *)authz_id, 1,
				 &conn->proxy_authz_ctrl);
	if (rc != LDAP_SUCCESS)
		return NULL;

	conn->proxy_authz_id = malloc(authz_id->bv_len);
	if (!conn->proxy_authz_id) {
		ldap_control_free(conn->proxy_authz_ctrl);
		conn->proxy_authz_ctrl = NULL;
		return NULL;
	}
	memcpy(conn->proxy_authz_id, authz_id->bv_val, authz_id->bv_len);
	conn->proxy_authz_id_len = authz_id->bv_len;

	return conn->proxy_authz_ctrl;
}

/*
 * Read table[field] as a berval into the caller-provided storage.
 *
 * Returns bv (filled) when the slot at table_pos is a table and table[field]
 * is a string. Returns NULL when the slot is not a table, the field is
 * absent, or the value is not a string. Length is taken via lua_tolstring,
 * so embedded NULs are preserved.
 *
 * The returned bv_val points into the Lua string and is valid only until
 * the caller next does anything that may release the value (Lua GC). In
 * practice callers consume it immediately; if you need to retain the bytes,
 * copy them out before any further Lua API call.
 */
static struct berval *
table_field_to_berval(lua_State *L, int table_pos, const char *field, struct berval *bv)
{
	if (!lua_istable(L, table_pos))
		return NULL;
	lua_getfield(L, table_pos, field);
	if (!lua_isstring(L, -1)) {
		lua_pop(L, 1);
		return NULL;
	}
	bv->bv_val = (char *)lua_tolstring(L, -1, &bv->bv_len);
	lua_pop(L, 1);
	return bv;
}

/*
** Typical error situation.
*/
static int faildirect (lua_State *L, const char *errmsg) {
	lua_pushnil (L);
	lua_pushstring (L, errmsg);
	return 2;
}


/** Retrieve a connection object from the first stack position
 *
 * @note Does not modify the lua stack, just verifies that the first
 *	   stack position is a valid connection object.
 *
 * @return conn_data pointer to the connection object.
 */
static conn_data *getconnection(lua_State *L)
{
	conn_data *conn = (conn_data *)luaL_checkudata(L, 1, LUALDAP_CONNECTION_METATABLE);
	luaL_argcheck(L, conn != NULL, 1, LUALDAP_PREFIX "LDAP connection expected");
	luaL_argcheck(L, conn->ld, 1, LUALDAP_PREFIX "LDAP connection is closed");

	return conn;
}


/**  Get a search object from the first upvalue position
 *
 */
static search_data_t *getsearch(lua_State *L)
{
	/* don't need to check upvalue's integrity */
	search_data_t *search = (search_data_t *)lua_touserdata(L, lua_upvalueindex(1));
	luaL_argcheck(L,search->conn != LUA_NOREF, 1, LUALDAP_PREFIX "LDAP search is closed");
	return search;
}


/*
** Set metatable of userdata on top of the stack.
*/
static void lualdap_setmeta (lua_State *L, const char *name) {
	luaL_getmetatable (L, name);
	lua_setmetatable (L, -2);
}


/*
** Error on option.
*/
static int option_error (lua_State *L, const char *name, const char *type) {
	return luaL_error (L, LUALDAP_PREFIX"invalid value on option `%s': %s expected, got %s", name, type, lua_typename (L, lua_type (L, -1)));
}


/*
** Push the value at table[name] onto the stack.
** The table MUST be at the given absolute stack index.
*/
static void strgettable (lua_State *L, int idx, const char *name) {
	lua_pushstring (L, name);
	lua_gettable (L, idx);
}

/*
** Get the field named name as a string from the table at idx.
*/
static const char *strtabparam (lua_State *L, int idx, const char *name, char *def) {
	strgettable (L, idx, name);
	if (lua_isnil (L, -1))
		return def;
	else if (lua_isstring (L, -1))
		return lua_tostring (L, -1);
	else {
		option_error (L, name, "string");
		return NULL;
	}
}

/*
** Get the field named name as an integer from the table at idx.
*/
static long longtabparam (lua_State *L, int idx, const char *name, int def) {
	strgettable (L, idx, name);
	if (lua_isnil (L, -1))
		return def;
	else if (lua_isnumber (L, -1))
		return (long)lua_tonumber (L, -1);
	else
		return option_error (L, name, "number");
}

/*
** Get the field named name as a double from the table at idx.
*/
static double numbertabparam(lua_State *L, int idx, const char *name, double def)
{
	strgettable (L, idx, name);
	if (lua_isnil(L, -1)) {
		return def;
	} else if (lua_isnumber(L, -1)) {
		return lua_tonumber(L, -1);
	}

	return option_error(L, name, "number");
}


/*
** Get the field named name as a boolean from the table at idx.
*/
static int booltabparam (lua_State *L, int idx, const char *name, int def) {
	strgettable (L, idx, name);
	if (lua_isnil (L, -1))
		return def;
	else if (lua_isboolean (L, -1))
		return lua_toboolean (L, -1);
	else
		return option_error (L, name, "boolean");
}

/*
** Get the field named name as light userdata from the table at idx.
*/
static search_data_t *userdatatabparam (lua_State *L, int idx, const char *name) {
	strgettable (L, idx, name);
	if (lua_isnil (L, -1))
		return NULL;
	else
		return (search_data_t *)lua_touserdata (L, -1);
}


/*
** Error on attribute's value.
*/
static void value_error (lua_State *L, const char *name) {
	luaL_error (L, LUALDAP_PREFIX"invalid value of attribute `%s' (%s)",
		name, lua_typename (L, lua_type (L, -1)));
}


/*
** Initialize attributes structure.
*/
static void A_init (attrs_data *attrs) {
	attrs->ai = 0;
	attrs->attrs[0] = NULL;
	attrs->vi = 0;
	attrs->values[0] = NULL;
	attrs->bi = 0;
}

/*
** Store the string on top of the stack on the attributes structure.
** Increment the bvals counter.
*/
static BerValue *A_setbval(lua_State *L, attrs_data *a, const char *n) {
	BerValue *ret = &(a->bvals[a->bi]);
	if (a->bi >= LUALDAP_MAX_VALUES) {
		luaL_error (L, LUALDAP_PREFIX"too many values");
		return NULL;
	} else if (!lua_isstring (L, -1)) {
		value_error (L, n);
		return NULL;
	}
	a->bvals[a->bi].bv_len = lua_strlen (L, -1);
	a->bvals[a->bi].bv_val = (char *)lua_tostring (L, -1);
	a->bi++;
	return ret;
}


/*
** Store a pointer to the value on top of the stack on the attributes structure.
*/
static BerValue **A_setval (lua_State *L, attrs_data *a, const char *n) {
	BerValue **ret = &(a->values[a->vi]);
	if (a->vi >= LUALDAP_ARRAY_VALUES_SIZE) {
		luaL_error (L, LUALDAP_PREFIX"too many values");
		return NULL;
	}
	a->values[a->vi] = A_setbval (L, a, n);
	a->vi++;
	return ret;
}

/*
** Store a NULL pointer on the attributes structure.
*/
static BerValue **A_nullval (lua_State *L, attrs_data *a) {
	BerValue **ret = &(a->values[a->vi]);
	if (a->vi >= LUALDAP_ARRAY_VALUES_SIZE) {
		luaL_error (L, LUALDAP_PREFIX"too many values");
		return NULL;
	}
	a->values[a->vi] = NULL;
	a->vi++;
	return ret;
}

/*
** Store the value of an attribute.
** Valid values are:
**	true => no values;
**	string => one value; or
**	table of strings => many values.
*/
static BerValue **A_tab2val(lua_State *L, attrs_data *a, const char *name) {
	int tab = lua_gettop (L);
	BerValue **ret = &(a->values[a->vi]);
	if (lua_isboolean (L, tab) && (lua_toboolean (L, tab) == 1)) /* true */
		return NULL;
	else if (lua_isstring (L, tab)) /* string */
		A_setval (L, a, name);
	else if (lua_istable (L, tab)) { /* list of strings */
		int i;
		int n = lua_objlen(L, tab);
		for (i = 1; i <= n; i++) {
			lua_rawgeti (L, tab, i); /* push table element */
			A_setval (L, a, name);
		}
		lua_pop (L, n);
	} else {
		value_error (L, name);
		return NULL;
	}
	A_nullval (L, a);
	return ret;
}


/*
** Set a modification value (which MUST be on top of the stack).
*/
static void A_setmod (lua_State *L, attrs_data *a, int op, const char *name) {
	if (a->ai >= LUALDAP_MAX_ATTRS) {
		luaL_error (L, LUALDAP_PREFIX"too many attributes");
		return;
	}
	a->mods[a->ai].mod_op = op;
	a->mods[a->ai].mod_type = (char *)name;
	a->mods[a->ai].mod_bvalues = A_tab2val (L, a, name);
	a->attrs[a->ai] = &a->mods[a->ai];
	a->ai++;
}


/*
** Convert a Lua table into an array of modifications.
** An array of modifications is a NULL-terminated array of LDAPMod's.
*/
static void A_tab2mod (lua_State *L, attrs_data *a, int tab, int op) {
	lua_pushnil (L); /* first key for lua_next */
	while (lua_next (L, tab) != 0) {
		/* attribute must be a string and not a number */
		if ((!lua_isnumber (L, -2)) && (lua_isstring (L, -2)))
			A_setmod (L, a, op, lua_tostring (L, -2));
		/* pop value and leave last key on the stack as next key for lua_next */
		lua_pop (L, 1);
	}
}


/*
** Terminate the array of attributes.
*/
static void A_lastattr (lua_State *L, attrs_data *a) {
	if (a->ai >= LUALDAP_MAX_ATTRS) {
		luaL_error (L, LUALDAP_PREFIX"too many attributes");
		return;
	}
	a->attrs[a->ai] = NULL;
	a->ai++;
}


/*
** Copy a string or a table of strings from Lua to a NULL-terminated array
** of C-strings.
*/
static int table2strarray (lua_State *L, int tab, char *array[], int limit) {
	if (lua_isstring (L, tab)) {
		if (limit < 2)
			return luaL_error (L, LUALDAP_PREFIX"too many arguments");
		array[0] = (char *)lua_tostring (L, tab);
		array[1] = NULL;
	} else if (lua_istable (L, tab)) {
		int i;
		int n = lua_objlen(L, tab);
		if (limit < (n+1))
			return luaL_error (L, LUALDAP_PREFIX"too many arguments");
		for (i = 0; i < n; i++) {
			lua_rawgeti (L, tab, i+1); /* push table element */
			if (lua_isstring (L, -1))
				array[i] = (char *)lua_tostring (L, -1);
			else {
				return luaL_error (L, LUALDAP_PREFIX"invalid value #%d", i+1);
			}
		}
		array[n] = NULL;
	} else
		return luaL_error (L, LUALDAP_PREFIX"bad argument #%d (table or string expected, got %s)", tab, lua_typename (L, lua_type (L, tab)));
	return 0;
}


/** Closure to return an actualised result from a msgid
 *
 * When we issue an operation agains the LDAP directory the LDAP client library
 * returns a message id. This message id is used to retrieve the result of the
 * search, mostly as a way of demuxing results from different operations on the
 * same connection.  This closure, has the connection, msgid, and
 *
 * Get the result message of an operation.
 * #1 upvalue == connection
 * #2 upvalue == msgid
 * #3 upvalue == result code of the message (ADD, DEL etc.) to be received.
 */
static int result_closure(lua_State *L) {
	int									rc = 0;
	conn_data							*conn = (conn_data *)lua_touserdata(L, lua_upvalueindex(1));
	int									msgid = (int)lua_tonumber(L, lua_upvalueindex(2));
	/*int res_code = (int)lua_tonumber(L, lua_upvalueindex(3));*/
	ngx_http_lua_socket_tcp_upstream_t	*u;
	ngx_http_request_t					*r;
	ngx_http_lua_ctx_t					*ctx;
	ngx_http_lua_co_ctx_t				*coctx;
	op_ctx_t							*op_ctx;
	int									timeout = luaL_optnumber(L, 1, 1000);

	/* Checks if conn->handle is currently NULL */
	luaL_argcheck(L, conn->ld, 1, LUALDAP_PREFIX "LDAP connection is closed");

	u = conn->u;
	r = u->request;

	conn->conn.connection->write->handler = ldap_socket_handler;
	conn->conn.connection->read->handler = ldap_socket_handler;
	ngx_add_timer(conn->conn.connection->read, timeout);

	op_ctx = ngx_alloc(sizeof(op_ctx_t), r->connection->log);
	op_ctx->u = u;
	op_ctx->conn = conn;
	op_ctx->msgid = msgid;

	rc = ldap_get_next_message_with_ctx(r, u, op_ctx);

	if (rc == NGX_ERROR) {
		dd("next_message read failed: %d", (int) u->ft_type);
		rc = ngx_http_lua_socket_tcp_receive_retval_handler(r, u, L);
		dd("tcp receive retval returned: %d", (int) rc);
		ngx_free(op_ctx);
		return rc;
	}

	if (rc == NGX_OK) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua tcp socket receive done in a single run");
		ngx_http_lua_socket_handle_write_success(r, u);

		return ldap_operation_receive_retval_handler(r, u, L);
	}

	/* rc == NGX_AGAIN */
	u->read_event_handler = ldap_search_handler;

	ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	coctx = ctx->cur_co_ctx;

	ngx_http_lua_cleanup_pending_operation(coctx);
	coctx->cleanup = ngx_http_lua_coctx_cleanup;
	coctx->data = op_ctx;

	if (ctx->entered_content_phase) {
		r->write_event_handler = ngx_http_lua_content_wev_handler;
	} else {
		r->write_event_handler = ngx_http_core_run_phases;
	}

	u->read_co_ctx = coctx;
	u->read_waiting = 1;
	u->read_prepare_retvals = ldap_operation_receive_retval_handler;

	dd("setting data to %p, coctx:%p", u, coctx);

	if (u->raw_downstream || u->body_downstream) {
		ctx->downstream = u;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "yielding from %s", __FUNCTION__);
	return lua_yield(L, 0);
}


/** Push a closure/future to process the LDAP result
 *
 * When this is evaluated later it'll have all the information it needs to translate the msgid
 * to an LDAPMessage representing the result of the operation.
 *
 * @note Expects userdata `conn_data` at position #1 on the stack.
 *
 * @param[in] L		lua_State.
 * @param[in] msgid	The message id returned from submitting the request.
 * @param[in] op	The type of result we're expecting.
 *			- LDAP_RES_ADD
 *			- LDAP_RES_DELETE
 *			- LDAP_RES_MODIFY
 *			- LDAP_RES_MODDN
 *			- LDAP_RES_SEARCH_ENTRY
 *			- LDAP_RES_SEARCH_RESULT
 */
static void result_closure_push(lua_State *L, ldap_int_t msgid, int op)
{
	/*
	 *	push connection (which should be position one on the stack)
	 *	This prevents the current connection frame from being consumed.
	 */
	lua_pushvalue(L, 1);			/* copy connection from stack position #1, back onto the stack */
	lua_pushnumber(L, msgid);		/* push msgid as #2 upvalue */
	lua_pushnumber(L, op);			/* push code as #3 upvalue */

	/* Consumes the last three pushed items */
	lua_pushcclosure(L, result_closure, 3);
}

/*
** Unbind from the directory.
** @param #1 LDAP connection.
** @return 1 in case of success; nothing when already closed.
*/
static int lualdap_close(lua_State *L) {
	conn_data *conn = (conn_data *)luaL_checkudata (L, 1, LUALDAP_CONNECTION_METATABLE);
	int was_open;

	luaL_argcheck(L, conn!=NULL, 1, LUALDAP_PREFIX"LDAP connection expected");
	was_open = conn->ld != NULL;

	/*
	 * Tears down ld plus the cached proxy authz control / id. Idempotent,
	 * so safe whether we're called explicitly or via __gc after an
	 * earlier close.
	 */
	conn_state_free(conn);

	if (!was_open) return 0;	/* preserve old "already closed -> nothing" return */
	lua_pushnumber (L, 1);
	return 1;
}


/*
** Add a new entry to the directory.
** @param #1 LDAP connection.
** @param #2 Socket object
** @param #3 String with new entry's DN.
** @param #4 Table with new entry's attributes and values.
** @param #5 Optional table with extra options: { proxy_id = "dn:..." }
** @return Function to process the LDAP result.
*/
static int lualdap_add(lua_State *L) {
	conn_data *conn = getconnection(L);
	ldap_pchar_t dn = (ldap_pchar_t)luaL_checkstring (L, 3);
	attrs_data attrs;
	ldap_int_t rc;
	int msgid;
	struct berval proxy_id_bv;
	LDAPControl *proxy_ctrl;
	LDAPControl *ctrls[2];
	LDAPControl **ctrls_p = ctrls;

	update_socket(L, conn);

	A_init(&attrs);
	if (lua_istable (L, 4)) A_tab2mod(L, &attrs, 4, LUALDAP_MOD_ADD);
	A_lastattr(L, &attrs);

	proxy_ctrl = proxy_control_add(conn, table_field_to_berval(L, 5, "proxy_id", &proxy_id_bv));
	if (proxy_ctrl) *ctrls_p++ = proxy_ctrl;
	*ctrls_p = NULL;

	rc = ldap_add_ext(conn->ld, dn, attrs.attrs, ctrls, NULL, &msgid);
	if (rc != LDAP_SUCCESS) return faildirect(L, ldap_err2string(rc));

	result_closure_push(L, msgid, LDAP_RES_ADD);
	return 1;
}

/*
** Compare a value against an entry.
** @param #1 LDAP connection.
** @param #2 Socket object
** @param #3 String with entry's DN.
** @param #4 String with attribute's name.
** @param #5 String with attribute's value.
** @param #6 Optional table with extra options: { proxy_id = "dn:..." }
** @return Function to process the LDAP result.
*/
static int lualdap_compare (lua_State *L) {
	conn_data *conn = getconnection (L);
	ldap_pchar_t dn = (ldap_pchar_t) luaL_checkstring (L, 3);
	ldap_pchar_t attr = (ldap_pchar_t) luaL_checkstring (L, 4);
	BerValue bvalue;
	ldap_int_t rc;
	int msgid;
	struct berval proxy_id_bv;
	LDAPControl *proxy_ctrl;
	LDAPControl *ctrls[2];
	LDAPControl **ctrls_p = ctrls;

	update_socket(L, conn);

	bvalue.bv_val = (char *)luaL_checkstring (L, 5);
	bvalue.bv_len = lua_strlen (L, 5);

	proxy_ctrl = proxy_control_add(conn, table_field_to_berval(L, 6, "proxy_id", &proxy_id_bv));
	if (proxy_ctrl) *ctrls_p++ = proxy_ctrl;
	*ctrls_p = NULL;

	rc = ldap_compare_ext (conn->ld, dn, attr, &bvalue, ctrls, NULL, &msgid);
	if (rc != LDAP_SUCCESS) return faildirect(L, ldap_err2string(rc));

	result_closure_push(L, msgid, LDAP_RES_COMPARE);
	return 1;
}

/*
** Delete an entry.
** @param #1 LDAP connection.
** @param #2 Socket object
** @param #3 String with entry's DN.
** @param #4 Optional table with extra options: { proxy_id = "dn:..." }
** @return Boolean.
*/
static int lualdap_delete (lua_State *L)
{
	conn_data	*conn = getconnection (L);
	ldap_pchar_t	dn = (ldap_pchar_t) luaL_checkstring (L, 3);
	ldap_int_t	rc;
	int		msgid;
	struct berval	proxy_id_bv;
	LDAPControl	*proxy_ctrl;
	LDAPControl	*ctrls[2];
	LDAPControl	**ctrls_p = ctrls;

	update_socket(L, conn);

	proxy_ctrl = proxy_control_add(conn, table_field_to_berval(L, 4, "proxy_id", &proxy_id_bv));
	if (proxy_ctrl) *ctrls_p++ = proxy_ctrl;
	*ctrls_p = NULL;

	rc = ldap_delete_ext (conn->ld, dn, ctrls, NULL, &msgid);
	if (rc != LDAP_SUCCESS) return faildirect(L, ldap_err2string(rc));

	result_closure_push(L, msgid, LDAP_RES_DELETE);
	return 1;
}

/*
** Convert a string into an internal LDAP_MOD operation code.
*/
static int op2code (const char *s) {
	if (!s)
		return LUALDAP_NO_OP;
	switch (*s) {
		case '+':
			return LUALDAP_MOD_ADD;
		case '-':
			return LUALDAP_MOD_DEL;
		case '=':
			return LUALDAP_MOD_REP;
		default:
			return LUALDAP_NO_OP;
	}
}


/*
** Modify an entry.
** @param #1 LDAP connection.
** @param #2 Socket object
** @param #3 String with entry's DN.
** @param #4, #5... Tables with modifications to apply.
**   Each modification table must have [1] set to '+', '-', or '='.
**   A trailing table without a valid operation code is treated as an options
**   table and may contain: { proxy_id = "dn:..." }
** @return True on success or nil, error message otherwise.
*/
static int lualdap_modify (lua_State *L) {
	conn_data *conn = getconnection (L);
	ldap_pchar_t dn = (ldap_pchar_t) luaL_checkstring (L, 3);
	attrs_data attrs;
	ldap_int_t rc;
	int msgid;
	int param = 4;
	struct berval proxy_id_bv;
	struct berval *proxy_id = NULL;
	LDAPControl *proxy_ctrl;
	LDAPControl *ctrls[2];
	LDAPControl **ctrls_p = ctrls;

	update_socket(L, conn);

	A_init (&attrs);
	while (lua_istable (L, param)) {
		const char *op_str;
		int op;

		/* Check operation code at [1]; a missing/invalid code marks an opts table. */
		lua_rawgeti(L, param, 1);
		op_str = lua_isstring(L, -1) ? lua_tostring(L, -1) : NULL;
		op = op2code(op_str);
		lua_pop(L, 1);

		if (op == LUALDAP_NO_OP) {
			proxy_id = table_field_to_berval(L, param, "proxy_id", &proxy_id_bv);
			break;
		}
		A_tab2mod (L, &attrs, param, op);
		param++;
	}
	A_lastattr(L, &attrs);

	proxy_ctrl = proxy_control_add(conn, proxy_id);
	if (proxy_ctrl) *ctrls_p++ = proxy_ctrl;
	*ctrls_p = NULL;

	rc = ldap_modify_ext (conn->ld, dn, attrs.attrs, ctrls, NULL, &msgid);
	if (rc != LDAP_SUCCESS) return faildirect(L, ldap_err2string(rc));

	result_closure_push(L, msgid, LDAP_RES_MODIFY);
	return 1;
}


/*
** Change the distinguished name of an entry.
** @param #1 LDAP connection.
** @param #2 Socket object
** @param #3 String with entry's current DN.
** @param #4 String with new RDN.
** @param #5 Optional new parent DN (nil to keep in place).
** @param #6 Boolean: delete old RDN values (default 0).
** @param #7 Optional table with extra options: { proxy_id = "dn:..." }
*/
static int lualdap_rename (lua_State *L) {
	conn_data	*conn = getconnection (L);
	ldap_pchar_t	dn;
	ldap_pchar_t	rdn;
	ldap_pchar_t	par;
	int		del;
	int		msgid;
	ldap_int_t	rc;
	struct berval	proxy_id_bv;
	LDAPControl	*proxy_ctrl;
	LDAPControl	*ctrls[2];
	LDAPControl	**ctrls_p = ctrls;

	update_socket(L, conn);

	dn = (ldap_pchar_t) luaL_checkstring(L, 3);
	rdn = (ldap_pchar_t) luaL_checkstring(L, 4);
	par = (ldap_pchar_t) luaL_optlstring(L, 5, NULL, NULL);
	del = luaL_optnumber(L, 6, 0);

	proxy_ctrl = proxy_control_add(conn, table_field_to_berval(L, 7, "proxy_id", &proxy_id_bv));
	if (proxy_ctrl) *ctrls_p++ = proxy_ctrl;
	*ctrls_p = NULL;

	rc = ldap_rename(conn->ld, dn, rdn, par, del, ctrls, NULL, &msgid);
	if (rc != LDAP_SUCCESS) return faildirect(L, ldap_err2string(rc));

	result_closure_push(L, msgid, LDAP_RES_MODDN);
	return 1;
}


/*
** Push an attribute value (or a table of values) on top of the stack.
** @param L lua_State.
** @param ld LDAP Connection.
** @param entry Current entry.
** @param attr Name of entry's attribute to get values from.
** @return 1 in case of success.
*/
static int push_values (lua_State *L, LDAP *ld, LDAPMessage *entry, char *attr) {
	int i, n;
	BerValue **vals = ldap_get_values_len (ld, entry, attr);
	n = ldap_count_values_len (vals);
	if (n == 0) /* no values */
		lua_pushboolean (L, 1);
	else if (n == 1) /* just one value */
		lua_pushlstring (L, vals[0]->bv_val, vals[0]->bv_len);
	else { /* Multiple values */
		lua_newtable (L);
		for (i = 0; i < n; i++) {
			lua_pushlstring (L, vals[i]->bv_val, vals[i]->bv_len);
			lua_rawseti (L, -2, i+1);
		}
	}
	ldap_value_free_len (vals);
	return 1;
}


/*
** Store entry's attributes and values at the given table.
** @param entry Current entry.
** @param tab Absolute stack index of the table.
*/
static void set_attribs (lua_State *L, LDAP *ld, LDAPMessage *entry, int tab) {
	char *attr;
	BerElement *ber = NULL;
	for (attr = ldap_first_attribute (ld, entry, &ber);
		attr != NULL;
		attr = ldap_next_attribute (ld, entry, ber))
	{
		lua_pushstring (L, attr);
		push_values (L, ld, entry, attr);
		lua_rawset (L, tab); /* tab[attr] = vals */
		ldap_memfree (attr);
	}
	ber_free (ber, 0); /* don't need to test if (ber == NULL) */
}

/*
** Get the distinguished name of the given entry and pushes it on the stack.
*/
static void push_dn(lua_State *L, LDAP *ld, LDAPMessage *entry) {
	char *dn = ldap_get_dn (ld, entry);
	lua_pushstring (L, dn);
	ldap_memfree (dn);
}

/*
** Release connection reference.
*/
static void search_close(lua_State *L, search_data_t *search)
{
	if (search->cookie != NULL) {
		ber_bvfree(search->cookie);
		search->cookie = NULL;
	}
	if (search->latest_cookie != NULL) {
		ber_bvfree(search->latest_cookie);
		search->latest_cookie = NULL;
	}

	switch (search->type) {
	case SEARCH_TYPE_PAGED:
	case SEARCH_TYPE_PERSISTENT:
	{
		conn_data *conn;
		lua_rawgeti(L, LUA_REGISTRYINDEX, search->conn);
		conn = lua_touserdata(L, -1);
		lua_pop(L, 1);

		/* Free up resources on the server allocated to paginated or persistent search.
		 * conn->ld may be NULL if the connection was closed before the search was GC'd. */
		if (conn->ld) ldap_abandon(conn->ld, search->msgid);
	}

	case SEARCH_TYPE_NORMAL:
		break;	/* Nothing to free here */
	}

	luaL_unref(L, LUA_REGISTRYINDEX, search->conn);
	search->conn = LUA_NOREF;
}

/*
** Get next LDAP message...
** @return #1 entry's distinguished name.
** @return #2 table with entry's attributes and values.
*/
static int ldap_get_next_message(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u) {
	ngx_http_lua_ctx_t *ctx;
	ngx_http_lua_co_ctx_t *coctx;
	op_ctx_t *op_ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	if (ctx == NULL) {
		return NGX_ERROR;
	}

	coctx = ctx->cur_co_ctx;
	if (!coctx) {
		coctx = u->read_co_ctx;
	}

	op_ctx = coctx->data;

	return ldap_get_next_message_with_ctx(r, u, op_ctx);
}

/** Iterator which is meant to
 *
 * Retrieve next message...
 * @return #1 entry's distinguished name.
 * @return #2 table with entry's attributes and values.
 */
static int next_message(lua_State *L) {
	search_data_t *search = getsearch (L);
	conn_data *conn;
	int rc;
	ngx_http_lua_socket_tcp_upstream_t *u;
	ngx_http_request_t *r;
	ngx_http_lua_ctx_t *ctx;
	ngx_http_lua_co_ctx_t *coctx;
	op_ctx_t *op_ctx;

	r = ngx_http_lua_get_req(L);
	if (r == NULL) {
		return luaL_error(L, "no request found");
	}
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "entering iterator aka next_message");

	lua_rawgeti (L, LUA_REGISTRYINDEX, search->conn);
	conn = (conn_data *)lua_touserdata(L, -1); /* get connection */
	lua_pop(L, 1);

	const int timeout = luaL_optnumber(L, 1, 1000);

	u = conn->u;

	conn->conn.connection->write->handler = ldap_socket_handler;
	conn->conn.connection->read->handler = ldap_socket_handler;
	if (timeout > 0) ngx_add_timer(conn->conn.connection->read, timeout);

	op_ctx = ngx_alloc(sizeof(op_ctx_t), r->connection->log);
	op_ctx->u = u;
	op_ctx->conn = conn;
	op_ctx->msgid = search->msgid;
	op_ctx->timeout = timeout;

	switch (rc = ldap_get_next_message_with_ctx(r, u, op_ctx)) {
	case NGX_ERROR:
	default:
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "next_message read failed: %d", (int) u->ft_type);
		rc = ngx_http_lua_socket_tcp_receive_retval_handler(r, u, L);
		dd("tcp receive retval returned: %d", (int) rc);
		ngx_free(op_ctx);
		return rc;

	case NGX_OK: {
		int nret;
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua tcp socket receive done in a single run");

		ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
		coctx = ctx->cur_co_ctx;
		coctx->data = op_ctx;

		nret = ldap_search_receive_retval_handler(r, u, L);
		if (nret == NGX_AGAIN) {
			/*
			 * INTERMEDIATE message was already buffered: retval handler consumed it,
			 * re-armed the LDAP socket, and set u->read_waiting=1.  We still need to
			 * yield so nginx can continue serving other events while we wait for the
			 * next LDAP message.  Set the HTTP write handler so flush/output works
			 * while we are suspended, then yield with an empty stack.
			 */
			if (ctx->entered_content_phase) {
				r->write_event_handler = ngx_http_lua_content_wev_handler;
			} else {
				r->write_event_handler = ngx_http_core_run_phases;
			}
			lua_settop(L, 0);
			return lua_yield(L, 0);
		}
		return nret;
	}

	case NGX_AGAIN:
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "waiting asynchronously for search result");
		u->read_event_handler = ldap_search_handler;

		ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
		coctx = ctx->cur_co_ctx;

		ngx_http_lua_cleanup_pending_operation(coctx);
		coctx->cleanup = ngx_http_lua_coctx_cleanup;

		coctx->data = op_ctx;

		if (ctx->entered_content_phase) {
			r->write_event_handler = ngx_http_lua_content_wev_handler;
		} else {
			r->write_event_handler = ngx_http_core_run_phases;
		}

		u->read_co_ctx = coctx;
		u->read_waiting = 1;
		u->read_prepare_retvals = ldap_search_receive_retval_handler;

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "setting data to %p, coctx:%p", u, coctx);

		if (u->raw_downstream || u->body_downstream) {
			ctx->downstream = u;
		}

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "yielding from %s", __FUNCTION__);
		lua_settop(L, 0);
		return lua_yield(L, 0);
	}
}


/*
** Convert a string to one of the possible scopes of the search.
*/
static int string2scope (lua_State *L, const char *s) {
	if ((s == NULL) || (*s == '\0'))
		return LDAP_SCOPE_DEFAULT;
	switch (*s) {
		case 'b':
			return LDAP_SCOPE_BASE;
		case 'o':
			return LDAP_SCOPE_ONELEVEL;
		case 's':
			return LDAP_SCOPE_SUBTREE;
		default:
			return luaL_error (L, LUALDAP_PREFIX"invalid search scope `%s'", s);
	}
}


/*
** Close the search object.
*/
static int lualdap_search_close(lua_State *L) {
	search_data_t *search = (search_data_t *)luaL_checkudata (L, 1, LUALDAP_SEARCH_METATABLE);
	luaL_argcheck (L, search!=NULL, 1, LUALDAP_PREFIX"LDAP search expected");
	if (search->conn == LUA_NOREF)
		return 0;
	search_close (L, search);
	lua_pushnumber (L, 1);
	return 1;
}

/** Create a search object and leaves it on top of the stack.
 *
 * @param L			lua_State.
 * @param conn_index	Index of the connection in the stack.
 * @param msgid		Message ID of the search operation.
 * @param cookie	Pointer to a berval structure containing the cookie for paging or persitence.
 * @param type		Type of search, one of:
 *					- SEARCH_TYPE_NORMAL for a normal search.
 *					- SEARCH_TYPE_PAGED for a paged search.
 *					- SEARCH_TYPE_PERSISTENT for a persistent search.
 */
static search_data_t *create_search(lua_State *L, int conn_index, int msgid, struct berval *cookie, search_type_t type)
{
	search_data_t *search = (search_data_t *)lua_newuserdata (L, sizeof (search_data_t));
	lualdap_setmeta(L, LUALDAP_SEARCH_METATABLE);
	search->conn = LUA_NOREF;
	search->msgid = msgid;
	search->cookie = cookie;
	search->type = type;
	search->morePages = FALSE;
	search->latest_cookie = NULL;

	lua_pushvalue(L, conn_index);
	search->conn = luaL_ref(L, LUA_REGISTRYINDEX);

	return search;
}

/*
** Ensure `name` is present in the NULL-terminated attrs[] array. If attrs is
** "all by default" (attrs[0] == NULL), expand to ["*", name, NULL] so the
** server still returns user attributes alongside the named operational one.
** Silently no-ops if there is no room in the array.
*/
static void ensure_attr_in_list(char *attrs[], const char *name, int max)
{
	int i;
	for (i = 0; i < max && attrs[i]; i++) {
		if (strcasecmp(attrs[i], name) == 0) return;
	}
	if (i >= max - 1) return;  /* full; leave alone */
	if (i == 0) {
		attrs[0] = "*";
		attrs[1] = (char *)name;
		attrs[2] = NULL;
		return;
	}
	attrs[i] = (char *)name;
	attrs[i + 1] = NULL;
}

/*
** Fill in the attrs array from the value at the given stack index.
**
** The slot may be:
**   - nil (or absent)  -> no explicit attrs requested (request all)
**   - a string         -> single-attribute list
**   - a table          -> array of attribute names
*/
static int get_attrs_param (lua_State *L, int idx, char *attrs[]) {
	if (lua_isnoneornil (L, idx)) {
		attrs[0] = NULL;
	} else if (lua_isstring (L, idx)) {
		attrs[0] = (char *)lua_tostring (L, idx);
		attrs[1] = NULL;
	} else if (lua_istable (L, idx)) {
		attrs[0] = NULL;
		if (table2strarray (L, idx, attrs, LUALDAP_MAX_ATTRS))
			return 0;
	} else {
		luaL_error (L, LUALDAP_PREFIX "invalid value for `attrs' (%s)",
			    lua_typename (L, lua_type (L, idx)));
		return 0;
	}
	return 1;
}


/*
** Fill in the struct timeval, according to the "timeout" field of the
** options table at the given stack index. Returns NULL when the slot is
** absent or the field is missing/zero.
*/
static struct timeval *get_timeout_param (lua_State *L, int idx, struct timeval *st) {
	double t;

	if (!lua_istable (L, idx))
		return NULL;

	t = numbertabparam (L, idx, "timeout", 0);
	st->tv_sec = (long)t;
	st->tv_usec = (long)(1000000 * (t - st->tv_sec));
	if (st->tv_sec == 0 && st->tv_usec == 0)
		return NULL;
	else
		return st;
}

/** Perform a persistent search operation.
 *
 * Initialises a persistent search operation on the given connection.
 * The connection is not returned to the pool until the search is closed.
 *
 * @param #1 LDAP connection.
 * @param #2 Socket object.
 * @param #3 String, base DN.
 * @param #4 String or nil, LDAP search filter.
 * @param #5 String, scope: "base" / "one" / "sub".
 * @param #6 String, table of strings, or nil, attributes to retrieve.
 *           entryUUID is always added if not already present.
 * @param #7 Optional table of options, may contain:
 *            - cookie    (string)  resume cookie from a prior sync
 *            - proxy_id  (string)  authzId for proxied authorization
 *
 * @return #1 Function to iterate over the result entries.
 * @return #2 Search handle.
 * The search result is defined as an upvalue of the iterator.
 */
static int lualdap_search_persistent(lua_State *L)
{
	conn_data			*conn = getconnection (L);

	ldap_pchar_t		base;
	ldap_pchar_t		filter;
	char				*attrs[LUALDAP_MAX_ATTRS];
	int					scope, rc;

	LDAPControl			ctrl = {0};
	LDAPControl			*ctrls[3];
	LDAPControl			**ctrls_p = ctrls;
	BerElement			*ber = NULL;
	static char const	*sync_ctl_oid = LDAP_CONTROL_SYNC;

	struct berval		 cookie_storage;
	struct berval		*cookie = NULL;   /* Resume cookie from a prior sync, if any */
	ngx_http_request_t	*r;
	int					msgid;
	int					opts_idx = 7;
	int					has_opts;
	int					saved_deref = LDAP_DEREF_NEVER;
	int					never_deref = LDAP_DEREF_NEVER;

	if (!lua_istable(L, 2))
		return luaL_error (L, LUALDAP_PREFIX "no connection socket");

	base = (ldap_pchar_t) luaL_checkstring (L, 3);
	filter = lua_isnoneornil (L, 4) ? NULL : (ldap_pchar_t) luaL_checkstring (L, 4);
	scope = string2scope (L, luaL_checkstring (L, 5));

	if (!get_attrs_param(L, 6, attrs))
		return 2;

	has_opts = lua_istable (L, opts_idx);

	/* Persistent searches always need entryUUID as a regular attribute.
	 * It is operational and so omitted unless explicitly requested; we want
	 * it in the entry as a fallback in case Sync State Control parsing ever
	 * fails. The persistent-search entry handler then strips it from attrs
	 * before returning, since metadata lives at the top level. */
	ensure_attr_in_list(attrs, "entryUUID", LUALDAP_MAX_ATTRS);

	/* Update internal connection to use new connection from pool */
	update_socket(L, conn);

	/* Sanity check */
	r = ngx_http_lua_get_req(L);
	if (r == NULL) return luaL_error(L, "no request found");

	/* Optional resume cookie. When provided, the server skips the refresh
	 * phase (or sends "present" markers for unchanged entries) and only
	 * ships changes since the cookie's CSN. */
	if (has_opts) {
		const char *c = strtabparam(L, opts_idx, "cookie", NULL);
		if (c) {
			cookie_storage.bv_val = (char *)c;
			cookie_storage.bv_len = strlen(c);
			cookie = &cookie_storage;
		}
	}

	ber = ber_alloc_t(LBER_USE_DER);
	if (ber == NULL) return luaL_error(L, LUALDAP_PREFIX "Failed allocating ber for sync control");

	/*
	 *	Might not necessarily have a cookie
	 */
	if (cookie) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, LUALDAP_PREFIX "Starting sync with cookie");

		ber_printf(ber, "{eOb}", LDAP_SYNC_REFRESH_AND_PERSIST, cookie, false);
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, LUALDAP_PREFIX "Starting sync without cookie");
		ber_printf(ber, "{eb}", LDAP_SYNC_REFRESH_AND_PERSIST, false);
	}

	rc = ber_flatten2(ber, &ctrl.ldctl_value, 0);
	if (rc < 0) {
		ber_free(ber, 1);
		return luaL_error(L, LUALDAP_PREFIX "Failed creating sync control");
	}

	memcpy(&ctrl.ldctl_oid, &sync_ctl_oid, sizeof(ctrl.ldctl_oid));
	ctrl.ldctl_iscritical = 1;

	*ctrls_p++ = &ctrl;	/* sync control is mandatory for persistent search */

	{
		struct berval proxy_id_bv;
		struct berval *proxy_id = has_opts ? table_field_to_berval(L, opts_idx, "proxy_id", &proxy_id_bv) : NULL;
		LDAPControl *proxy_ctrl = proxy_control_add(conn, proxy_id);
		if (proxy_ctrl) *ctrls_p++ = proxy_ctrl;
	}
	*ctrls_p = NULL;

	/*
	 * Force derefAliases = neverDerefAliases for the duration of this
	 * search. The syncprov overlay rejects syncrepl SearchRequests with
	 * any other deref value ("illegal value for derefAliases", protocol
	 * error 2). LDAP_OPT_DEREF is session-wide on the handle, so save
	 * and restore the caller's setting after the request is queued.
	 * ldap_search_ext is non-blocking - it just serialises and sends -
	 * so restoring immediately after the call is correct; the value is
	 * only consulted by libldap when building the request PDU.
	 */
	ldap_get_option(conn->ld, LDAP_OPT_DEREF, &saved_deref);
	ldap_set_option(conn->ld, LDAP_OPT_DEREF, &never_deref);

	rc = ldap_search_ext(conn->ld, base, scope, filter, attrs, 0,
						 ctrls, NULL, NULL, 0, &msgid);

	ldap_set_option(conn->ld, LDAP_OPT_DEREF, &saved_deref);

	ber_free(ber, 1);

	if (rc != LDAP_SUCCESS) return luaL_error(L, LUALDAP_PREFIX "%s", ldap_err2string(rc));

	{
		search_data_t *s = create_search(L, 1, msgid, NULL, SEARCH_TYPE_PERSISTENT);
		/* Seed latest_cookie with the resume cookie so any "present" markers
		 * or pre-checkpoint entries are stamped with at least the input
		 * cookie until the server issues a fresher one. */
		if (cookie) s->latest_cookie = ber_bvdup(cookie);
	}
	lua_pushvalue (L, -1);
	lua_pushcclosure(L, next_message, 1);	/* This is the ierator the caller can use to page out results */
	lua_pushvalue(L, -2);
	lua_remove(L, -3);

	return 2;
}

/*
** Perform a search operation.
**
** @param #1 LDAP connection.
** @param #2 Socket object.
** @param #3 String, base DN.
** @param #4 String or nil, LDAP search filter.
** @param #5 String, scope: "base" / "one" / "sub".
** @param #6 String, table of strings, or nil, attributes to retrieve.
** @param #7 Optional table of options, may contain:
**            - attrsonly  (bool)         default false
**            - sizelimit  (int)          default LDAP_NO_LIMIT
**            - pagesize   (int)          default 0 (no paging)
**            - search     (light userdata) prior search handle for paging
**            - timeout    (number)       seconds, default 0 (no timeout)
**            - proxy_id   (string)       authzId for proxied authorization
**
** @return #1 Function to iterate over the result entries.
** @return #2 Search handle (for more_pages / continued paging).
** The search result is defined as an upvalue of the iterator.
*/
static int lualdap_search(lua_State *L)
{
	conn_data *conn = getconnection (L);
	ldap_pchar_t base;
	ldap_pchar_t filter;
	char *attrs[LUALDAP_MAX_ATTRS];
	int scope, attrsonly, rc, sizelimit, pagesize;
	struct timeval st, *timeout;
	LDAPControl *pageControl = NULL;
	LDAPControl *ctrls[3];
	LDAPControl **ctrls_p = ctrls;
	struct berval *cookie = NULL;   /* Cookie for paging */
	search_data_t * current_search;
	ngx_http_request_t	  *r;
	int msgid;
	int opts_idx = 7;
	int has_opts;

	if (!lua_istable (L, 2))
		return luaL_error(L, LUALDAP_PREFIX "no connection socket");

	base = (ldap_pchar_t) luaL_checkstring (L, 3);
	filter = lua_isnoneornil (L, 4) ? NULL : (ldap_pchar_t) luaL_checkstring (L, 4);
	scope = string2scope (L, luaL_checkstring (L, 5));

	if (!get_attrs_param (L, 6, attrs))
		return 2;

	has_opts = lua_istable (L, opts_idx);

	/* Update internal connection to use new connection from pool */
	update_socket(L, conn);

	r = ngx_http_lua_get_req(L);
	if (r == NULL) {
		return luaL_error(L, "no request found");
	}

	/* get optional parameters */
	if (has_opts) {
		attrsonly = booltabparam(L, opts_idx, "attrsonly", 0);
		sizelimit = longtabparam(L, opts_idx, "sizelimit", LDAP_NO_LIMIT);
		pagesize = longtabparam(L, opts_idx, "pagesize", 0);
		current_search = userdatatabparam(L, opts_idx, "search");
		timeout = get_timeout_param(L, opts_idx, &st);
	} else {
		attrsonly = 0;
		sizelimit = LDAP_NO_LIMIT;
		pagesize = 0;
		current_search = NULL;
		timeout = NULL;
	}

	if (pagesize) {
		if (current_search) {
			cookie = current_search->cookie;
		}
		rc = ldap_create_page_control(conn->ld, pagesize, cookie, 1, &pageControl);
		if (rc != LDAP_SUCCESS) {
			return luaL_error (L, LUALDAP_PREFIX"%s", ldap_err2string (rc));
		}
		*ctrls_p++ = pageControl;
	}

	{
		struct berval proxy_id_bv;
		struct berval *proxy_id = has_opts ? table_field_to_berval(L, opts_idx, "proxy_id", &proxy_id_bv) : NULL;
		LDAPControl *proxy_ctrl = proxy_control_add(conn, proxy_id);
		if (proxy_ctrl) *ctrls_p++ = proxy_ctrl;
	}
	*ctrls_p = NULL;

	rc = ldap_search_ext(conn->ld, base, scope, filter, attrs, attrsonly,
						 ctrls, NULL, timeout, sizelimit, &msgid);
	if (rc != LDAP_SUCCESS)
		return luaL_error (L, LUALDAP_PREFIX"%s", ldap_err2string (rc));

	ldap_control_free(pageControl);

	if (current_search) {
		create_search(L, 1, msgid, current_search->cookie, SEARCH_TYPE_NORMAL);
		/* Set cookie to NULL to avoid double free */
		current_search->cookie = NULL;
	} else {
		create_search(L, 1, msgid, cookie, SEARCH_TYPE_PAGED);
	}
	lua_pushvalue(L, -1);
	lua_pushcclosure(L, next_message, 1);	/* This is the ierator the caller can use to page out results */
	lua_pushvalue (L, -2);
	lua_remove(L, -3);

	return 2;
}

/*
** Return the name of the object's metatable.
** This function is used by `tostring'.
*/
static int lualdap_conn_tostring (lua_State *L) {
	char buff[100];
	conn_data *conn = (conn_data *)lua_touserdata (L, 1);
	if (conn->ld == NULL)
		strcpy (buff, "closed");
	else
		sprintf (buff, "%p", conn);
	lua_pushfstring (L, "%s (%s)", LUALDAP_CONNECTION_METATABLE, buff);
	return 1;
}

/*
** Return the name of the object's metatable.
** This function is used by `tostring'.
*/
static int lualdap_search_tostring(lua_State *L) {
	char buff[100];
	search_data_t *search = (search_data_t *)lua_touserdata (L, 1);
	luaL_argcheck(L,search->conn != LUA_NOREF,1,LUALDAP_PREFIX"LDAP search is closed");
	if (search->conn == LUA_NOREF)
		strcpy (buff, "closed");
	else
		sprintf (buff, "%p", search);
	lua_pushfstring (L, "%s (%s)", LUALDAP_SEARCH_METATABLE, buff);
	return 1;
}

/*
** Return true if there more pages to be read
** or false otherwise
*/
static int lualdap_more_pages (lua_State *L) {
	search_data_t *search = (search_data_t *)lua_touserdata (L, 1);
	lua_pushboolean (L, search->morePages);
	return 1;
}

/*
** Create a metatable.
*/
static int lualdap_createmeta (lua_State *L) {
	const luaL_Reg conn_methods[] = {
		{"close", lualdap_close},
		{"add", lualdap_add},
		{"compare", lualdap_compare},
		{"delete", lualdap_delete},
		{"modify", lualdap_modify},
		{"rename", lualdap_rename},
		{"search", lualdap_search},
		{"search_persistent", lualdap_search_persistent},
		{"init_fd", lualdap_init_fd},
		{NULL, NULL}
	};

	const luaL_Reg search_methods[] = {
		{"more_pages", lualdap_more_pages},
		{NULL, NULL}
	};

	/*
 	 *	Push a new metatable onto the stack, and add it to
   	 *	the global metatable registry. NGINX uses separate
	 *	interpreter states per-worker thread, so there's no
	 *	synchornisation issues.  The request will not
	 *	containue until the metatable is populated.
  	 *
	 *	requires are also cached on a per-worker basis, so
	 *	we don't need to check if the metatables already exist.
	 */
	if (!luaL_newmetatable(L, LUALDAP_CONNECTION_METATABLE)) return 0;

	/*
  	 *	Adds the connection functions to the connection
	 *	We use this instead of luaL_openlib to avoid creating
	 *	or modifying globals, which NGINX complains about.
  	 */
	luaL_setfuncs(L, conn_methods, 0);

	/* define metamethods */
	lua_pushliteral(L, "__gc");
	lua_pushcfunction(L, lualdap_close);
	lua_settable(L, -3);

	/*
	 *	Sets the table of functions loaded with luaL_setfuncs
  	 *	as the index table.  This makes them callable from
	 *	the scope of the table to which the metatable is bound
 	 */
	lua_pushliteral(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);

	lua_pushliteral(L, "__tostring");
	lua_pushcfunction(L, lualdap_conn_tostring);
	lua_settable(L, -3);

	lua_pushliteral(L, "__metatable");
	lua_pushliteral(L,LUALDAP_PREFIX "you're not allowed to get this metatable");
	lua_settable(L, -3);

	/*
	 *  Create reusable metatable for searches
	 */
	if (!luaL_newmetatable(L, LUALDAP_SEARCH_METATABLE)) return 0;

	/*
  	 *	Adds the search functions to the search metatable
	 *	We use this instead of luaL_openlib to avoid creating
	 *	or modifying globals, which can create races when
	 *	used with NGINX.
	 */
	luaL_setfuncs(L, search_methods, 0);

	lua_pushliteral(L, "__gc");
	lua_pushcfunction(L, lualdap_search_close);
	lua_settable(L, -3);

	lua_pushliteral(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);

	lua_pushliteral(L, "__tostring");
	lua_pushcfunction(L, lualdap_search_tostring);
	lua_settable(L, -3);

	lua_pushliteral(L, "__metatable");
	lua_pushliteral(L,LUALDAP_PREFIX "you're not allowed to get this metatable");
	lua_settable(L, -3);

	return 0;
}

/** Adds metadata to the module table at the top of the stack
 *
 */
static void set_info (lua_State *L) {
	lua_pushliteral(L, "_COPYRIGHT");
	lua_pushliteral(L, "Copyright (C) 2023-2025 Canada 12952386 Inc, 2003-2007 Kepler Project");
	lua_settable(L, -3);
	lua_pushliteral(L, "_DESCRIPTION");
	lua_pushliteral(L, "LuaLDAP is a simple interface from Lua to an LDAP client");
	lua_settable(L, -3);
	lua_pushliteral(L, "_VERSION");
	lua_pushliteral(L, "LuaLDAP 1.1.1");
	lua_settable(L, -3);
}


/** Main symbol exported by lualdap
 *
 *
 */
int luaopen_ngx_lualdap (lua_State *L) {
	/* Each entry in this table registers a method callable from Lua */
	struct luaL_Reg lualdap[] = {
		{"init", lualdap_init},			/* */
		{"get_fd", lualdap_get_fd},
		{NULL, NULL},
	};

	/*
 	 *	Registers metatables in the global metatable registry
   	 *	Should not leave anything on the Lua stack.
   	 */
	lualdap_createmeta(L);
	lua_newtable(L);
	luaL_setfuncs(L, lualdap, 0);

	set_info(L);

	return 1;
}

/*
 *  Module takes no configuration, but we must provide a ctx else
 *  nginx segvs on config test.
 */
static ngx_http_module_t  ngx_lualdap_module_ctx = {
	NULL,				  /* preconfiguration */
	NULL,				  /* postconfiguration */

	NULL,				  /* create main configuration */
	NULL,				  /* init main configuration */

	NULL,				  /* create server configuration */
	NULL,				  /* merge server configuration */

	NULL,				  /* create location configuration */
	NULL				  /* merge location configuration */
};

ngx_module_t  ngx_lualdap = {
	NGX_MODULE_V1,
	&ngx_lualdap_module_ctx,	  /* module context */
	NULL,				  /* module directives */
	NGX_HTTP_MODULE,		  /* module type */
	NULL,				  /* init master */
	NULL,				  /* init module */
	NULL,				  /* init process */
	NULL,				  /* init thread */
	NULL,				  /* exit thread */
	NULL,				  /* exit process */
	NULL,				  /* exit master */
	NGX_MODULE_V1_PADDING
};
