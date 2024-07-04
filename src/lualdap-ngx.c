#define LDAP_PROTO_TCP 1 /* ldap:  */
#define LDAP_PROTO_UDP 2 /* reserved */
#define LDAP_PROTO_IPC 3 /* ldapi: */
#define LDAP_PROTO_EXT 4 /* user-defined socket/sockbuf */

enum {
    SOCKET_OP_CONNECT,
    SOCKET_OP_READ,
    SOCKET_OP_WRITE
};

typedef struct {
    ngx_http_lua_socket_tcp_upstream_t *u;
    conn_data *conn;
    int msgid;
    LDAPMessage *res;
    int ldap_rc;
} op_ctx_t;

static void ldap_search_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u);
static void ngx_http_auth_ldap_close_connection(conn_data *c, ngx_log_t *log);
static void ngx_http_lua_socket_handle_write_success(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u);
static void ngx_http_lua_socket_handle_read_success(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u);
static void ngx_http_lua_socket_handle_write_success(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u);
static void ngx_http_lua_coctx_cleanup(void *data);
static void ngx_http_lua_content_wev_handler(ngx_http_request_t *r);
static int ngx_http_lua_socket_tcp_receive_retval_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);
static void ldap_socket_handler(ngx_event_t *ev);
static int ldap_get_next_message (ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u);
static int ldap_get_next_message_with_ctx (ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, op_ctx_t *op_ctx);
static void ngx_http_lua_socket_handle_read_error(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, ngx_uint_t ft_type);
static int ldap_bind_receive_retval_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);
static int ldap_operation_receive_retval_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);
static int ngx_http_lua_socket_read_error_retval_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);

/*
 * Forward declaration of functions in lualdap.c
 */
static int faildirect (lua_State *L, const char *errmsg);
static search_data *getsearch (lua_State *L);
static void lualdap_setmeta (lua_State *L, const char *name);
static void set_attribs (lua_State *L, LDAP *ld, LDAPMessage *entry, int tab);
static void push_dn (lua_State *L, LDAP *ld, LDAPMessage *entry);
static void search_close (lua_State *L, search_data *search);


#if 0
int dump(void *myStruct, long size)
{
    unsigned int i;
    const unsigned char * const px = (unsigned char*)myStruct;
    for (i = 0; i < size; ++i) {
        if( i % (sizeof(int) * 8) == 0){
            printf("\n%08X ", i);
        }
        else if( i % 4 == 0){
            printf(" ");
        }
        printf("%02X", px[i]);
    }

    printf("\n\n");
    return 0;
}

void stackdump_g(lua_State* l)
{
    int i;
    int top = lua_gettop(l);
 
    printf("total in stack %d\n",top);
 
    for (i = 1; i <= top; i++)
    {  /* repeat for each level */
        printf("  ");  /* put a separator */
        int t = lua_type(l, i);
        switch (t) {
            case LUA_TSTRING:  /* strings */
                printf("string: '%s'\n", lua_tostring(l, i));
                break;
            case LUA_TBOOLEAN:  /* booleans */
                printf("boolean %s\n",lua_toboolean(l, i) ? "true" : "false");
                break;
            case LUA_TNUMBER:  /* numbers */
                printf("number: %g\n", lua_tonumber(l, i));
                break;
	    case LUA_TUSERDATA:
		printf("Userdata: %x\n", lua_touserdata(l,i));
		break;
            default:  /* other values */
                printf("%s %s\n", lua_typename(l, t), lua_tostring(l,i));
                break;
        }
    }
    printf("\n");  /* end the listing */
}
#endif

#ifdef NGX_DEBUG
static char const *nginx_rcode_to_str(int rc)
{
    switch (rc) {
    case NGX_OK:
        return "NGX_OK";

    case NGX_DECLINED:
        return "NGX_DECLINED";

    case NGX_AGAIN:
        return "NGX_AGAIN";

    case NGX_DONE:
        return "NGX_DONE";

    default:
        return "UNKNOWN";
    }
}
#endif

static int
ldap_operation_receive_retval_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L)
{
	int n, rc, err, ret = 1;
	char *mdn, *msg;
	ngx_http_lua_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	ngx_http_lua_co_ctx_t *coctx = ctx->cur_co_ctx;
	op_ctx_t *op_ctx = coctx->data;

	conn_data *conn = u->peer.connection->data;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "entered %s", __FUNCTION__);

	if (u->ft_type) {
		if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_TIMEOUT) {
			u->no_close = 1;
		}

		n = ngx_http_lua_socket_read_error_retval_handler(r, u, L);
		lua_pushliteral(L, "");
		ngx_free(op_ctx);
		return n + 1;
	}

	rc = ldap_parse_result(conn->ld, op_ctx->res, &err, &mdn, &msg, NULL, NULL, 1);
	if (rc != LDAP_SUCCESS)
		return faildirect(L, ldap_err2string (rc));

	switch (err) {
	case LDAP_SUCCESS:
	case LDAP_COMPARE_TRUE:
		lua_pushboolean (L, 1);
		break;
	case LDAP_COMPARE_FALSE:
		lua_pushboolean (L, 0);
		break;
	default:
		lua_pushnil (L);
		int nb_strings = 2;
		lua_pushliteral (L, LUALDAP_PREFIX);
		if (msg) {
			lua_pushstring (L, msg);
			lua_pushliteral (L, " ");
			nb_strings = 4;
		}
		lua_pushstring (L, ldap_err2string(err));
		lua_concat (L, nb_strings);
		lua_pushnumber (L, err);
		ret = 3;
	}
	ldap_memfree(mdn);
	ldap_memfree(msg);
	return ret;
}

static void update_socket(lua_State *L, conn_data *conn) {
	ngx_http_lua_socket_tcp_upstream_t *u;

	/* Update internal connection to use new connection from pool */
	luaL_checktype(L, 2, LUA_TTABLE);

	lua_rawgeti(L, 2, 1); /* Push nginx socket onto stack */
	u = lua_touserdata(L, -1);
	lua_pop(L, 1);

	if (u == NULL || u->peer.connection == NULL) {
	    return;
	}

	/* Update pointers */
	conn->conn = u->peer;
	conn->u = u;
	u->peer.connection->data = conn;
}


static void
ldap_search_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u)
{
	ngx_connection_t            *c;

	c = u->peer.connection;

	if (c->read->timedout) {
		c->read->timedout = 0;
		ngx_http_lua_socket_handle_read_error(r, u, NGX_HTTP_LUA_SOCKET_FT_TIMEOUT);
		return;
	}

#if 1
	if (c->read->timer_set) {
		ngx_del_timer(c->read);
	}
#endif

	(void) ldap_get_next_message(r, u);
}

static int
ngx_http_lua_socket_prepare_error_retvals(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L, ngx_uint_t ft_type)
{
    u_char           errstr[NGX_MAX_ERROR_STR];
    u_char          *p;

    if (ft_type & (NGX_HTTP_LUA_SOCKET_FT_RESOLVER
                   | NGX_HTTP_LUA_SOCKET_FT_SSL))
    {
        return 2;
    }

    lua_pushnil(L);

    if (ft_type & NGX_HTTP_LUA_SOCKET_FT_TIMEOUT) {
        lua_pushliteral(L, "timeout");

    } else if (ft_type & NGX_HTTP_LUA_SOCKET_FT_CLOSED) {
        lua_pushliteral(L, "closed");

    } else if (ft_type & NGX_HTTP_LUA_SOCKET_FT_BUFTOOSMALL) {
        lua_pushliteral(L, "buffer too small");

    } else if (ft_type & NGX_HTTP_LUA_SOCKET_FT_NOMEM) {
        lua_pushliteral(L, "no memory");

    } else if (ft_type & NGX_HTTP_LUA_SOCKET_FT_CLIENTABORT) {
        lua_pushliteral(L, "client aborted");

    } else {
        if (u->socket_errno) {
#if defined(nginx_version) && nginx_version >= 9000
            p = ngx_strerror(u->socket_errno, errstr, sizeof(errstr));
#else
            p = ngx_strerror_r(u->socket_errno, errstr, sizeof(errstr));
#endif
            /* for compatibility with LuaSocket */
            ngx_strlow(errstr, errstr, p - errstr);
            lua_pushlstring(L, (char *) errstr, p - errstr);

        } else {
            lua_pushliteral(L, "error");
        }
    }

    return 2;
}

static int
ngx_http_lua_socket_read_error_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    ngx_uint_t          ft_type;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "entered %s", __FUNCTION__);

    if (u->read_co_ctx) {
        u->read_co_ctx->cleanup = NULL;
    }

    ft_type = u->ft_type;
    u->ft_type = 0;

    if (u->no_close) {
        u->no_close = 0;

    } else {
//        ngx_http_lua_socket_tcp_finalize_read_part(r, u);
    }

    return ngx_http_lua_socket_prepare_error_retvals(r, u, L, ft_type);
}

static int
ldap_search_receive_retval_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L)
{
	search_data *search = getsearch (L);
	int n, ret;
	conn_data *conn;
	ngx_http_lua_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	ngx_http_lua_co_ctx_t *coctx = ctx->cur_co_ctx;
	op_ctx_t *op_ctx = coctx->data;
    
	lua_rawgeti (L, LUA_REGISTRYINDEX, search->conn);
	conn = (conn_data *)lua_touserdata (L, -1); /* get connection */
	lua_pop(L, 1); // Remove from stack

	LDAPControl **returnedControls = NULL;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "got search result");

	if (u->ft_type) {
		n = ngx_http_lua_socket_read_error_retval_handler(r, u, L);
		lua_pushliteral(L, "");
		return n + 1;
	}

	// Check status of last call to ldap_result
	if (op_ctx->ldap_rc == LDAP_RES_SEARCH_RESULT) { /* last message => nil */
		ldap_parse_result(conn->ld, op_ctx->res, NULL, NULL, NULL, NULL, &returnedControls, 0);

		if (search->cookie != NULL) {
			ber_bvfree(search->cookie);
			search->cookie = NULL;
		}

		/*
	 	 * Parse the page control returned to get the cookie and
	 	 * determine whether there are more pages.
	 	 */
		ldap_parse_page_control(conn->ld, returnedControls, NULL, &search->cookie);

		/* cookie is only set when more pages are available */
		if (search->cookie && search->cookie->bv_len > 0) {
			search->morePages = TRUE;
		} else {
			search->morePages = FALSE;
		}

		/* Cleanup the controls used. */
		if (returnedControls) ldap_controls_free(returnedControls);

		if (!search->morePages) {
			/* close search object to avoid reuse */
			search_close (L, search);
		}
		ret = 0;
	} else {
		LDAPMessage *msg = ldap_first_message (conn->ld, op_ctx->res);
		int msgtype = ldap_msgtype(msg)
		switch (msgtype)) {
		case LDAP_RES_SEARCH_ENTRY: {
			LDAPMessage *entry = ldap_first_entry (conn->ld, msg);
			push_dn (L, conn->ld, entry);
			lua_newtable (L);
			set_attribs (L, conn->ld, entry, lua_gettop (L));
			ret = 2; /* two return values */
			break;
		}
/*No reference to LDAP_RES_SEARCH_REFERENCE on MSDN. Maybe there is a replacement to it?*/
#ifdef LDAP_RES_SEARCH_REFERENCE
		case LDAP_RES_SEARCH_REFERENCE: {
			LDAPMessage *ref = ldap_first_reference (conn->ld, msg);
			push_dn (L, conn->ld, ref); /* is this supposed to work? */
			lua_pushnil (L);
			ret = 2; /* two return values */
			break;
		}
#endif
		case LDAP_RES_SEARCH_RESULT:
			/* close search object to avoid reuse */
			search_close (L, search);
			ret = 0;
			break;
		default:
			ldap_msgfree(op_ctx->res);
			op_ctx->res = NULL; /* For debugging */
			ngx_free(op_ctx);
			return luaL_error(L, LUALDAP_PREFIX"error on search result chain, unexpected msgtype (%d), msgtype);
		}
	}
	ldap_msgfree(op_ctx->res);
	op_ctx->res = NULL; /* For debugging */
	ngx_free(op_ctx);
	return ret;
}

/** Perform a non-blocking read on a an LDAP handle
 *
 * @param[in] r         The current HTTP request.
 * @param[in] u         NGINX socket used for the LDAP connection.
 * @param[in] op_ctx    the current LDAP operation.
 * @return
 *  - NGX_AGAIN no data available.
 *  - NGX_ERROR an error ocurred (read failed)
 */
static int ldap_get_next_message_with_ctx(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, op_ctx_t *op_ctx)
{
	conn_data *ldap_conn = op_ctx->conn;
	struct timeval timeout = { .tv_sec = 0, .tv_usec = 0 };
	int rc, ret;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "entering ldap_get_next_search_message_with_ctx");

	rc = ldap_result(ldap_conn->ld, op_ctx->msgid, LDAP_MSG_ONE, &timeout, &op_ctx->res);
	if (rc == 0)
		// No data to be read
		ret = NGX_AGAIN;
	else if (rc == -1)
		ret = NGX_ERROR;
	else {
		if (ldap_msgid(op_ctx->res) != op_ctx->msgid) {
			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ldap_get_next_search_message: Message with unknown ID received, ignoring. Got %d, expected %d",
                           ldap_msgid(op_ctx->res), op_ctx->msgid);
			ret = NGX_ERROR;
		} else {
			op_ctx->ldap_rc = rc;

		       /*
			*  Resumes the current request
			*/
			ngx_http_lua_socket_handle_read_success(r, u);
			ret = NGX_OK;
		}
	}

	return ret;
}

/*** OpenLDAP SockBuf implementation over nginx socket functions ***/

static int
ngx_http_auth_ldap_sb_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
    sbiod->sbiod_pvt = arg;
    return 0;
}

static int
ngx_http_auth_ldap_sb_remove(Sockbuf_IO_Desc *sbiod)
{
    conn_data *c = (conn_data *)sbiod->sbiod_pvt;

    (void)c; /* 'c' would be left unused on debug builds */

    sbiod->sbiod_pvt = NULL;
    return 0;
}

static int
ngx_http_auth_ldap_sb_close(Sockbuf_IO_Desc *sbiod)
{
//    conn_data *c = (conn_data *)sbiod->sbiod_pvt;


//    if (!c->conn.connection->read->error && !c->conn.connection->read->eof) {
//        if (ngx_shutdown_socket(c->conn.connection->fd, SHUT_RDWR) == -1) {
//            ngx_connection_error(c->conn.connection, ngx_socket_errno, ngx_shutdown_socket_n " failed");
//            //ngx_http_auth_ldap_close_connection(c);
//            return -1;
//        }
//    }

    return 0;
}

static int
ngx_http_auth_ldap_sb_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
    conn_data *c = (conn_data *)sbiod->sbiod_pvt;


    switch (opt) {
    case LBER_SB_OPT_DATA_READY:
	    if (c->conn.connection->read->ready) {
		return 1;
	    }
	    return 0;
    }

    return 0;
}

static ber_slen_t
ngx_http_auth_ldap_sb_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    conn_data *c = (conn_data *)sbiod->sbiod_pvt;
    ber_slen_t ret;


    ret = c->conn.connection->recv(c->conn.connection, buf, len);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return -1;
    }

    return ret;
}

static ber_slen_t
ngx_http_auth_ldap_sb_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    conn_data *c = (conn_data *)sbiod->sbiod_pvt;
    ber_slen_t ret;


    ret = c->conn.connection->send(c->conn.connection, buf, len);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return 0;
    }

    return ret;
}

static Sockbuf_IO ngx_http_auth_ldap_sbio =
{
    ngx_http_auth_ldap_sb_setup,
    ngx_http_auth_ldap_sb_remove,
    ngx_http_auth_ldap_sb_ctrl,
    ngx_http_auth_ldap_sb_read,
    ngx_http_auth_ldap_sb_write,
    ngx_http_auth_ldap_sb_close
};

static void
ngx_http_lua_coctx_cleanup(void *data)
{
    op_ctx_t			*op_ctx;
    ngx_http_lua_co_ctx_t	*coctx = data;


    op_ctx = coctx->data;
    if (op_ctx == NULL) {
        return;
    }

//    ngx_http_lua_socket_tcp_finalize(u->request, u);
}

static void
ngx_http_lua_content_wev_handler(ngx_http_request_t *r)
{
    ngx_http_lua_ctx_t          *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return;
    }

    (void) ctx->resume_handler(r);
}

static int
ngx_http_lua_socket_tcp_receive_retval_handler(ngx_http_request_t *r,
                                               ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua tcp socket receive return value handler");

    return 0;
}

/** Creates a new LDAP connection from an Nginx stream socket
 *
 * @param[in] L     current Lua environment
 */
static int lualdap_init(lua_State *L) {
	ngx_http_request_t *r;
	ngx_http_lua_ctx_t *ctx;

	/* 
	 *  Should not be passed in any arguments init_fd(...) is 
	 *  called on the connection object.
	 *
	 *  This takes an Nginx socket(ngx.socket.tcp) and any bind parameters 
	 *  and creates a actual connection handle.
	 */
	if (lua_gettop(L) != 0) {
		return luaL_error(L, "expecting zero arguments, but got %d", lua_gettop(L));
	}

	/*
	 *  Get the current HTTP request running through NGINX
	 *
	 *  This is just a sanity check.
	 */
	r = ngx_http_lua_get_req(L);
	if (r == NULL) {
		return luaL_error(L, "no request found");
	}

	/*
	 *  Get a handle to the LUA module running within NGINX
	 *
	 *  This is just a sanity check.
	 */
	ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	if (ctx == NULL) return luaL_error(L, "no ctx found");

	/*
	 *  Allocate new connection data in the Lua envirionment
	 *  this holds the LDAP * and the file descriptor.
	 *
	 *  This is pushed onto the Lua stack.
	 */
	(void)lua_newuserdata(L, sizeof(conn_data)); /* New data pushed onto Lua stack */

	/*
	 *  Associate methods with the connection object.
	 *  The metatable itself is defined in lualdap_createmeta, which 
	 *  is called once when we initialise the library.
	 *
	 *  This metatable makes the following Lua methods available for the handle:
	 *  - init_fd   lualdap_init_fd - Initialise a new libldap handle
	 *              from an existing file descriptor.
	 *              We use this to build a connection around an 
	 *              NGINX stream socket that NGINX has already
	 *              opened.
	 *  - close     lualdap_close - Close the current connection.
	 *  - add       lualdap_add - Add a new LDAP object.
	 *  - compare   lualdap_compare - Compare something? 
	 *  - delete    lualdap_delete - Delete an LDAP object.
	 *  - modify    lualdap_modify - Modify an LDAP object.
	 *  - rename    lualdap_rename - Rename an LDAP object.
	 *  - search    lualdap_search - Search for an LDAP object.
	 */
	lualdap_setmeta(L, LUALDAP_CONNECTION_METATABLE);

	return 1; /* We pushed one entry onto the stack, our new connection handle */
}

static int lualdap_get_fd(lua_State *L) {
	ngx_http_lua_socket_tcp_upstream_t *u;
	ngx_http_request_t          *r;

	r = ngx_http_lua_get_req(L);
	if (r == NULL) {
		return luaL_error(L, "no request found");
	}

	if (lua_gettop(L) != 1) {
		return luaL_error(L, "expecting 1 argument, but got %d", lua_gettop(L));
	}

	luaL_checktype(L, 1, LUA_TTABLE);

	lua_rawgeti(L, 1, 1); /* Push nginx socket onto stack */
	u = lua_touserdata(L, -1);
	lua_pop(L, 1);

	if (u == NULL || u->peer.connection == NULL) {
		return 0;
        }

	lua_pushnumber(L, u->peer.connection->fd);

	return 1;
}

/** Create an OpenLDAP handle from a file descriptor, and bind it to an LDAP connection handle
 *
 * We expect LUA arguments:
 * - 1 (object)     our connection object.
 * - 2 (sock)       the NGINX socket.
 * - 3 (bind_user)  the user to bind as.
 * - 4 (bind_pass)  the password to bind with.
 * - 5 (bind)       whether we need to rebind the socket.
 *                  we may not need to if we're using a
 *                  a cached connection.
 * - 6 (sasl_mech)  the sasl mechanism to use when binding - optional.
 */
static int lualdap_init_fd(lua_State *L) {
	char *path = NULL;
	ngx_http_lua_socket_tcp_upstream_t *u;
	ngx_http_request_t *r;
	ngx_http_lua_ctx_t *ctx;
	ngx_http_lua_co_ctx_t *coctx;
	conn_data *conn = (conn_data *)luaL_checkudata(L, 1, LUALDAP_CONNECTION_METATABLE);
	op_ctx_t *op_ctx;
	int msgid;

	/*
	 *  Lua arguments 3-5
	 */
	ldap_pchar_t user;
	const char *password;
	int do_bind;
	/*
	 *  Optional arg 6
	 */
	const char *sasl_mech;

	/*
	 *  If the object this method is being called from does not have
	 *  a metatable of type LUALDAP_CONNECTION_METATABLE, something
	 *  has gone terribly wrong.
	 */
	if (conn == NULL) {
		return luaL_error(L, "init_fd called on non-connection object");
	}

	r = ngx_http_lua_get_req(L);    /* current NGINX request */
	if (r == NULL) {
		return luaL_error(L, "no request found");
	}
	
	/*
	 *  Check we have four additional arguments on the stack
	 */
	if (lua_gettop(L) < 5) {
		return luaL_error(L, "expecting >= 5 arguments, but got %d", lua_gettop(L));
	}

    	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, LUALDAP_PREFIX"Creating new connection from cosocket");

	/*
	 *  Basic sanity check to make sure this is an NGINX socket
	 *  really we should check the metadata too.
	 */
	luaL_checktype(L, 2, LUA_TTABLE);

	/*
	 *  Push nginx socket onto stack
	 */
	lua_rawgeti(L, 2, 1);

	/*
	 *  Get the ngx_http_lua_socket_tcp_upstream_t from the LUA object.
	 *  This is the C handle that contains all the details of the NGINX 
	 *  stream socket.
	 */
	u = lua_touserdata(L, -1);
	lua_pop(L, 1);

	/*
	 *  Connection closed? Or is this a logic error??
	 */
	if (u == NULL || u->peer.connection == NULL) {
		return 0;
	}

	/*
	 *  u->peer.connection is the underlying socket.
	 *
	 *  ngx_event_t is an event structure with details of the event 
	 *  passed in to the handler function.
	 *
	 *  write->handler gets called on write, read->handler gets called
	 *  on read.  It's not clear why we use a single callback here, 
	 *  but that callback does distinguish between the event types.
	 */
	u->peer.connection->write->handler = ldap_socket_handler;
	u->peer.connection->read->handler = ldap_socket_handler;

	user = (ldap_pchar_t) luaL_optstring (L, 3, NULL);
	password = luaL_optstring (L, 4, NULL);
	do_bind = lua_toboolean (L, 5);
	conn->conn = u->peer;

    	/*
     	 *  Check for optional arguments
     	 */
    	if (lua_gettop(L) >= 6 && !lua_isnil(L, 6)) {
        	sasl_mech = luaL_checkstring(L, 6);
		lua_pop(L, 6);  /* Clear the optional arg too */
    	} else {
        	sasl_mech = LDAP_SASL_SIMPLE;
		lua_pop(L, 5);
    	}
	/*
	 *  Allow us to get back to our connection handle if we're only
	 *  passed ngx_http_lua_socket_tcp_upstream_t.
	 */
	u->peer.connection->data = conn;
	conn->u = u;

	/*
	 *  Initialise an LDAP handle around the FD from the NGINX stream
	 *  socket.
	 *
	 *  LDAP_PROTO_EXT is used to stop allow us to use custom sockbuf
	 *  handlers for the connection so that we can plumb it into the
	 *  NGINX socket.
	 */
	if (ldap_init_fd(u->peer.connection->fd, LDAP_PROTO_EXT, (const char *) path, &conn->ld) != LDAP_SUCCESS) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, LUALDAP_PREFIX"ldap_init_fd failed");
		return 0;
	}

	/*
	 *  Set the socket option to version 3... It's not clear why this
	 *  is necessary.
	 */
	conn->version = LDAP_VERSION3;
	if (ldap_set_option(conn->ld, LDAP_OPT_PROTOCOL_VERSION, &conn->version) != LDAP_OPT_SUCCESS) {
		return faildirect(L, LUALDAP_PREFIX"Error setting LDAP version");
	}

	{
		Sockbuf *sb;
		
		if (ldap_get_option(conn->ld, LDAP_OPT_SOCKBUF, (void *)&sb) != LDAP_OPT_SUCCESS) {
		    return 0;
		}
		
		/*
		 *  Here we reuse the socket bio functions from the NGINX 
		 *  auth_ldap module.  This saves us from writing duplicate
		 *  functions I/O functions.
		 */
		ber_sockbuf_add_io(sb, &ngx_http_auth_ldap_sbio, LBER_SBIOD_LEVEL_PROVIDER, (void *)conn);
	}

	/*
	 *  Return 1 to indicate success.
	 */
	if (!do_bind) {
		lua_pushinteger(L, 1);
		return 1;
	}

	/*
	 *  Add a timer that periodically fires dummy read events
	 *  every second. Not sure why this is done.
	 */
	ngx_add_timer(u->peer.connection->read, 1000);

	/*
	*  Bind the LDAP handle using credentials...
	*
	*  FIXME: We should support SASL binds with the EXTERNAL
	*  mech here.
	*/
	{
		struct berval cred;
		int rc;
		
		memcpy(&cred.bv_val, &password, sizeof(cred.bv_val));
		cred.bv_len = strlen(password);
		
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, LUALDAP_PREFIX"Binding LDAP connection");
		rc = ldap_sasl_bind(conn->ld, (const char *) user, sasl_mech, &cred, NULL, NULL, &msgid);
		if (rc != LDAP_SUCCESS) {
		    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, LUALDAP_PREFIX"Bind failed immediately");
		    return faildirect(L, ldap_err2string(rc));
		}
	}

	/*
	 *  Allocate an op_ctx, this wraps a single LDAP message
	 *  in a local structure.
	 */
	 op_ctx = ngx_calloc(sizeof(op_ctx_t), r->connection->log);
	 op_ctx->msgid = msgid;
	 op_ctx->u = u;
	 op_ctx->conn = conn;

	{
		int rc;
		
		switch (ldap_get_next_message_with_ctx(r, u, op_ctx)) {
		case NGX_ERROR:
		default:
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, LUALDAP_PREFIX"ldap next message read failed: %d", (int) u->ft_type);
			rc = ngx_http_lua_socket_tcp_receive_retval_handler(r, u, L);
		    	dd("tcp receive retval returned: %d", (int) rc);
		    	return rc;
		
		case NGX_OK:
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, LUALDAP_PREFIX"lua tcp socket receive done in a single run");
			return ldap_bind_receive_retval_handler(r, u, L);
		
		case NGX_AGAIN:
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, LUALDAP_PREFIX"waiting for bind result asynchronously");
			u->read_event_handler = ldap_search_handler;
			
			ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
			coctx = ctx->cur_co_ctx;
			
			ngx_http_lua_cleanup_pending_operation(coctx);
			
			dd("setting data to %p, coctx:%p", u, coctx);
			coctx->cleanup = ngx_http_lua_coctx_cleanup;
			coctx->data = op_ctx;
			
			if (ctx->entered_content_phase) {
				r->write_event_handler = ngx_http_lua_content_wev_handler;
			} else {
				r->write_event_handler = ngx_http_core_run_phases;
			}
			
			u->read_co_ctx = coctx;
			u->read_waiting = 1;
			u->read_prepare_retvals = ldap_bind_receive_retval_handler; /* Resumption function */
			
			if (u->raw_downstream || u->body_downstream) {
				ctx->downstream = u;
			}
			
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "yielding from %s", __FUNCTION__);
			return lua_yield(L, 0);
		}
	}
}


static void
ldap_socket_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    conn_data *conn;
    ngx_http_request_t *r;
    ngx_http_log_ctx_t *ctx;

    ngx_http_lua_socket_tcp_upstream_t  *u;

    c = ev->data;
    conn = c->data;
    u = conn->u;
    r = u->request;
    c = r->connection;

    if (c->fd != (ngx_socket_t) -1) {  /* not a fake connection */
        ctx = c->log->data;
        ctx->current_request = r;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "ldap socket handler for \"%V?%V\", wev %d", &r->uri,
                   &r->args, (int) ev->write);

    if (ev->write) {
        u->write_event_handler(r, u);

    } else {
	/* Since we've got a read event mark write as successful */
	ngx_http_lua_socket_handle_write_success(r,u);

        u->read_event_handler(r, u);
    }

    ngx_http_run_posted_requests(c);
}

static void
ngx_http_lua_socket_dummy_handler(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua tcp socket dummy handler");
}

static ngx_int_t
ngx_http_lua_socket_tcp_resume_helper(ngx_http_request_t *r, int socket_op)
{
    int nret;
    lua_State *vm;
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_http_lua_ctx_t *ctx;
    ngx_http_lua_co_ctx_t *coctx;
    op_ctx_t *op_ctx;
    int nreqs;

    ngx_http_lua_socket_tcp_retval_handler  prepare_retvals;

    ngx_http_lua_socket_tcp_upstream_t      *u;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "entered %s", __FUNCTION__);

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->resume_handler = ngx_http_lua_wev_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "--> lua tcp operation done, resuming lua thread");


    coctx = ctx->cur_co_ctx;

    dd("coctx: %p", coctx);

    op_ctx = coctx->data;
    u = op_ctx->u;

    switch (socket_op) {
    case SOCKET_OP_CONNECT:
    case SOCKET_OP_WRITE:
        prepare_retvals = u->write_prepare_retvals;
        break;

    case SOCKET_OP_READ:
        prepare_retvals = u->read_prepare_retvals;
        break;

    default:
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua tcp socket calling prepare retvals handler %p, "
                   "u:%p", prepare_retvals, u);

    nret = prepare_retvals(r, u, ctx->cur_co_ctx->co);
    if (nret == NGX_AGAIN) {
        return NGX_DONE;
    }

    c = r->connection;
    vm = ngx_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = ngx_http_lua_run_thread(vm, r, ctx, nret);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_lua_run_thread returned %s, nreqs=%d", nginx_rcode_to_str(rc), nreqs);
    switch (rc) {
    case NGX_DONE:
        ngx_http_lua_finalize_request(r, NGX_DONE);
        /* FALL-THROUGH */

    case NGX_AGAIN:
        rc = ngx_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_lua_run_posted_threads returned %s", nginx_rcode_to_str(rc));
        return rc;

    default:
        if (ctx->entered_content_phase) {
            ngx_http_lua_finalize_request(r, rc);
            return NGX_DONE;
        }
        return rc;
    }
}

static ngx_int_t
ngx_http_lua_socket_tcp_read_resume(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "entered %s", __FUNCTION__);

    return ngx_http_lua_socket_tcp_resume_helper(r, SOCKET_OP_READ);
}

static void
ngx_http_lua_socket_handle_read_success(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u)
{
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "entered %s", __FUNCTION__);

#if 1
    u->read_event_handler = ngx_http_lua_socket_dummy_handler;
#endif

    if (u->read_waiting) {
        u->read_waiting = 0;

        coctx = u->read_co_ctx;
        coctx->cleanup = NULL;
        u->read_co_ctx = NULL;

        ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
        if (ctx == NULL) {
            return;
        }

        ctx->resume_handler = ngx_http_lua_socket_tcp_read_resume;
        ctx->cur_co_ctx = coctx;

        ngx_http_lua_assert(coctx && (!ngx_http_lua_is_thread(ctx)
                            || coctx->co_ref >= 0));

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua tcp socket waking up the current request (read)");

        r->write_event_handler(r);
    }
}

static ngx_int_t
ngx_http_lua_socket_tcp_write_resume(ngx_http_request_t *r)
{
    return ngx_http_lua_socket_tcp_resume_helper(r, SOCKET_OP_WRITE);
}

static void
ngx_http_lua_socket_handle_write_success(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u)
{
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;

#if 1
    u->write_event_handler = ngx_http_lua_socket_dummy_handler;
#endif

    if (u->write_waiting) {
        u->write_waiting = 0;

        coctx = u->write_co_ctx;
        coctx->cleanup = NULL;
        u->write_co_ctx = NULL;

        ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
        if (ctx == NULL) {
            return;
        }

        ctx->resume_handler = ngx_http_lua_socket_tcp_write_resume;
        ctx->cur_co_ctx = coctx;

        ngx_http_lua_assert(coctx && (!ngx_http_lua_is_thread(ctx) || coctx->co_ref >= 0));

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua tcp socket waking up the current request (read)");

        r->write_event_handler(r);
    }
}

static int
ldap_bind_receive_retval_handler(ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L)
{
	int n;
	ngx_http_lua_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	ngx_http_lua_co_ctx_t *coctx = ctx->cur_co_ctx;
	op_ctx_t *op_ctx = coctx->data;
	conn_data *ldap_conn = op_ctx->conn;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, LUALDAP_PREFIX"received bind result");

	r = ngx_http_lua_get_req(L);
	if (r == NULL) {
		return luaL_error(L, "no request found");
	}

	if (u->ft_type) {
		if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_TIMEOUT) {
		    u->no_close = 1;
		}
		
		n = ngx_http_lua_socket_read_error_retval_handler(r, u, L);
		lua_pushliteral(L, "");
		ngx_free(op_ctx);
		
		return n + 1;
	}

	if (ldap_conn->ld == NULL) {
		ngx_http_auth_ldap_close_connection(ldap_conn, r->connection->log);
		return luaL_error(L, "ldap_bind_receive_retval_handler: no LDAP connection");
	}

    	ldap_msgfree(op_ctx->res);
	op_ctx->res = NULL;	/* For debugging */
	ngx_free(op_ctx);

	lua_pushinteger(L, 1);
	return 1;
}

static void
ngx_http_auth_ldap_close_connection(conn_data *c, ngx_log_t *log)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "entered %s", __FUNCTION__);

    if (c->ld) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "http_auth_ldap: Unbinding from the server");
        ldap_unbind_ext(c->ld, NULL, NULL);
        /* Unbind is always synchronous, even though the function name does not end with an '_s'. */
        c->ld = NULL;
    }
}

static void
ngx_http_lua_socket_handle_read_error(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, ngx_uint_t ft_type)
{
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lua tcp socket handle read error");

    u->ft_type |= ft_type;

#if 0
    ngx_http_lua_socket_tcp_finalize(r, u);
#endif

    u->read_event_handler = ngx_http_lua_socket_dummy_handler;

    if (u->read_waiting) {
        u->read_waiting = 0;

        coctx = u->read_co_ctx;
        coctx->cleanup = NULL;
        u->read_co_ctx = NULL;

        ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

        ctx->resume_handler = ngx_http_lua_socket_tcp_read_resume;
        ctx->cur_co_ctx = coctx;

        ngx_http_lua_assert(coctx && (!ngx_http_lua_is_thread(ctx)
                            || coctx->co_ref >= 0));

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua tcp socket waking up the current request");

        r->write_event_handler(r);
    }
}
