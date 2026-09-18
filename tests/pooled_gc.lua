--
-- Torture coverage for the lualdap connection finalizer.
--
-- The test reproduces the use-after-free in the pooled-connection `__gc`
-- finalizer. The finalizer (lualdap_close -> conn_state_free ->
-- ldap_unbind_ext) writes an UNBIND PDU through the ngx_connection_t that
-- backed the cosocket, after the cosocket has closed and after nginx has
-- freed and reused that ngx_connection_t.
--
-- The use-after-free was seen on production (pr-za-ldap01, 2026-09-18). The
-- reused slot was an inbound TLS client, so the finalizer faulted in
-- ngx_ssl_write on a NULL c->ssl. The fault does not depend on the send
-- handler. A plaintext slot faults in ngx_unix_send or ngx_connection_error
-- instead. Under AddressSanitizer the write to the freed ngx_connection_t is
-- reported directly, before any fault.
--
-- The harness skips the test unless STRESS_TESTS=1, so the fast functional
-- cycle stays quick. The dedicated stress workflow runs nginx under ASan and
-- fails on the ASan log.
--
-- The test drives /ldap-pooled, which copies dapman's connection lifecycle
-- (SubMan src/dapman/ldap.lua, ldap:get_connection): the cosocket returns to
-- the nginx keepalive pool, the connection object is cached by fd in a
-- per-worker table, and conn:close() is never called. mode=drop returns
-- without setkeepalive, so the cosocket closes with the request while the
-- cosocket's connection object stays cached and orphaned. mode=gc runs
-- collectgarbage(), so the orphan's finalizer runs immediately.
--

local luaunit = require('luaunit')
local socket  = require('socket')

local m = {}

local STRESS = os.getenv('STRESS_TESTS') == '1'
if not STRESS then
    -- An empty table is what the run_tests harness expects from a class with
    -- no runnable cases for this build.
    return m
end

local NGINX_HOST = os.getenv('NGINX_HOST') or '127.0.0.1'
local NGINX_PORT = tonumber(os.getenv('NGINX_PORT') or os.getenv('TEST_PORT') or '8090')

-- Iterations of the drop/drop/gc cycle. The buggy module crashes well inside
-- the default (8 to 93 in local runs); a fixed module survives every one.
local GC_ITERATIONS = tonumber(os.getenv('STRESS_GC_ITERATIONS')) or 500

-- Send one HTTP/1.0 GET and read the whole response. Returns the body, or nil
-- plus an error when the connection cannot be made, which is how a crashed
-- single-process nginx presents to the next request.
local function http_get(path)
    local tcp = socket.tcp()
    tcp:settimeout(10)
    local ok, err = tcp:connect(NGINX_HOST, NGINX_PORT)
    if not ok then
        return nil, 'connect: ' .. tostring(err)
    end
    tcp:send('GET /' .. path .. ' HTTP/1.0\r\nHost: ' .. NGINX_HOST .. '\r\n\r\n')
    local body = tcp:receive('*a')
    tcp:close()
    return body
end

-- Prove nginx is still serving by hitting the no-LDAP endpoint.
local function nginx_alive()
    local body = http_get('test')
    return body ~= nil and body:find('Testing 123', 1, true) ~= nil
end

--- Orphan a pooled connection every cycle and force the connection finalizer to run
---
--- The test asserts that nginx survives every cycle. Each drop leaves a
--- connection object cached for a cosocket that has closed. A later drop on
--- the same fd replaces the cache entry and orphans the first connection
--- object. The gc then finalizes the orphaned connection object, and
--- lualdap_close writes an UNBIND PDU through the freed ngx_connection_t. See
--- the file header for the full chain.
function m:TestPooledFinalizerUnbindUseAfterFree()
    for iter = 1, GC_ITERATIONS do
        local _, err = http_get('ldap-pooled?mode=drop')
        luaunit.assertNil(err, 'iter ' .. iter .. ' (drop): ' .. tostring(err))
        http_get('ldap-pooled?mode=drop')
        http_get('ldap-pooled?mode=gc')

        if iter % 25 == 0 then
            luaunit.assertTrue(nginx_alive(),
                'nginx unresponsive after ' .. iter .. ' finalizer cycles')
        end
    end

    luaunit.assertTrue(nginx_alive(), 'nginx unresponsive after finalizer torture')
end

return m
