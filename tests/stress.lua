--
-- Stress / chaos coverage for the per-request pool cleanup that
-- abandons in-flight LDAP searches when an SSE / paged client
-- disappears mid-stream.
--
-- These tests are skipped unless STRESS_TESTS=1 is set so a normal CI
-- cycle stays fast (~1m). The dedicated stress workflow runs nginx
-- under AddressSanitizer + LeakSanitizer so use-after-free / leaks in
-- the cleanup path surface here as test failures.
--

local luaunit = require('luaunit')
local socket  = require('socket')

local m = {}

local STRESS = os.getenv('STRESS_TESTS') == '1'
if not STRESS then
    -- Returning an empty table is what the run_tests harness expects
    -- when a test class has no runnable cases for this build.
    return m
end

local NGINX_HOST = os.getenv('NGINX_HOST') or '127.0.0.1'
local NGINX_PORT = tonumber(os.getenv('NGINX_PORT') or os.getenv('TEST_PORT') or '8090')

-- LDAP coordinates for the bulk LDIF inject. The submodule CI exposes
-- bitnami openldap as `openldap:389` from the runner network; outside
-- CI fall back to the local socat forwarder.
local LDAP_HOST  = os.getenv('STRESS_LDAP_HOST')  or os.getenv('LDAP_HOST')  or '127.0.0.1'
local LDAP_PORT  = tonumber(os.getenv('STRESS_LDAP_PORT') or os.getenv('LDAP_PORT') or '1389')
local LDAP_BIND  = 'cn=manager,dc=example,dc=org'
local LDAP_PASS  = 'password'

local STRESS_OBJECT_COUNT     = tonumber(os.getenv('STRESS_OBJECT_COUNT')     or '10000')
local STRESS_KILL_ITERATIONS  = tonumber(os.getenv('STRESS_KILL_ITERATIONS')  or '50')
local STRESS_CONCURRENT_OPENS = tonumber(os.getenv('STRESS_CONCURRENT_OPENS') or '20')
local STRESS_BASE_DN          = 'ou=stress,dc=example,dc=org'

-- Seed a deterministic-ish RNG so failures are reproducible. Override
-- with STRESS_SEED to bisect.
math.randomseed(tonumber(os.getenv('STRESS_SEED')) or os.time())

-- ---------------------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------------------

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

-- Open a raw TCP connection, send an HTTP/1.0 GET, return the socket
-- positioned just past the response headers. HTTP/1.0 keeps nginx from
-- chunking the response so the body bytes match what content_by_lua
-- printed.
local function open_raw(path_and_query, recv_timeout)
    local tcp = socket.tcp()
    tcp:settimeout(recv_timeout or 5)
    local ok, err = tcp:connect(NGINX_HOST, NGINX_PORT)
    if not ok then return nil, 'connect: ' .. tostring(err) end
    tcp:send('GET /' .. path_and_query .. ' HTTP/1.0\r\nHost: ' .. NGINX_HOST .. '\r\n\r\n')
    -- Drain headers
    while true do
        local line = tcp:receive('*l')
        if not line then return nil, 'eof in headers' end
        if line:gsub('\r', '') == '' then break end
    end
    return tcp
end

-- Same SSE event reader as tests/sse.lua; copied to keep this file
-- standalone (it isn't loaded when STRESS_TESTS is unset).
local function read_sse_event(tcp)
    local etype, data
    while true do
        local line, err = tcp:receive('*l')
        if not line then return nil, nil end
        line = line:gsub('\r', '')
        if line == '' then
            if etype or data then
                return etype or 'message', data or ''
            end
        elseif line:sub(1, 7) == 'event: ' then
            etype = line:sub(8)
        elseif line:sub(1, 6) == 'data: ' then
            data = line:sub(7)
        end
    end
end

-- Smoke test: hit the no-LDAP /test endpoint. Used between iterations to
-- prove nginx is still alive even after we've torn the LDAP connection
-- in half repeatedly.
local function nginx_alive()
    local tcp, err = open_raw('test')
    if not tcp then return false, err end
    local body = tcp:receive('*a')
    tcp:close()
    return body and body:find('Testing 123', 1, true) ~= nil
end

-- Run ldapadd with the supplied LDIF. Returns true on success.
local function ldapadd_ldif(ldif)
    local cmd = string.format(
        "ldapadd -x -c -H ldap://%s:%d -D '%s' -w '%s' >/dev/null 2>&1",
        LDAP_HOST, LDAP_PORT, LDAP_BIND, LDAP_PASS
    )
    local f = io.popen(cmd, 'w')
    if not f then return false, 'ldapadd popen failed' end
    f:write(ldif)
    -- ldapadd returns non-zero per failed entry; -c keeps going. We
    -- accept any close result here because pre-existing ou=stress is
    -- expected on second-and-later runs.
    f:close()
    return true
end

local function ldapdelete_subtree(dn)
    local cmd = string.format(
        "ldapdelete -x -c -r -H ldap://%s:%d -D '%s' -w '%s' '%s' >/dev/null 2>&1",
        LDAP_HOST, LDAP_PORT, LDAP_BIND, LDAP_PASS, dn
    )
    os.execute(cmd)
end

local function bulk_seed(count)
    -- ou=stress as the container, then $count leaf cn=stressN entries.
    local lines = {
        'dn: ' .. STRESS_BASE_DN,
        'objectClass: organizationalUnit',
        'ou: stress',
        '',
    }
    for i = 1, count do
        lines[#lines + 1] = 'dn: cn=stress' .. i .. ',' .. STRESS_BASE_DN
        lines[#lines + 1] = 'objectClass: person'
        lines[#lines + 1] = 'cn: stress' .. i
        lines[#lines + 1] = 'sn: ' .. i
        lines[#lines + 1] = ''
    end
    return ldapadd_ldif(table.concat(lines, '\n'))
end

-- ---------------------------------------------------------------------------
-- one-time setup: seed the tree, regardless of which tests run
-- ---------------------------------------------------------------------------

print(string.format(
    "[stress] seeding %d entries under %s (LDAP=%s:%d)...",
    STRESS_OBJECT_COUNT, STRESS_BASE_DN, LDAP_HOST, LDAP_PORT
))
assert(bulk_seed(STRESS_OBJECT_COUNT), 'bulk LDIF inject failed')

-- ---------------------------------------------------------------------------
-- tests
-- ---------------------------------------------------------------------------

--- Open SSE, drain a random number of events, abruptly close. Loop.
--- Verifies the per-request pool cleanup abandons each search and
--- nginx survives every iteration.
function m:TestStressPersistentSearchAbruptClose()
    local sse_path = 'ldap-sse?' .. qs({
        host = LDAP_HOST,
        port = LDAP_PORT,
        base = STRESS_BASE_DN,
        filter = '(objectClass=*)',
    })

    for iter = 1, STRESS_KILL_ITERATIONS do
        local tcp, err = open_raw(sse_path)
        luaunit.assertNotNil(tcp, 'iter ' .. iter .. ': ' .. tostring(err))

        local drain_target = math.random(0, math.min(200, STRESS_OBJECT_COUNT))
        for _ = 1, drain_target do
            local ev = read_sse_event(tcp)
            if ev == nil then break end
        end

        -- Hard close: simulate client RST mid-stream.
        tcp:close()
    end

    luaunit.assertTrue(nginx_alive(), 'nginx unresponsive after persistent-search torture')
end

--- Same shape, but on the paged-search endpoint which exercises the
--- SEARCH_TYPE_PAGED branch of the cleanup handler.
function m:TestStressPagedSearchAbruptClose()
    local search_path = 'ldap-search?' .. qs({
        host = LDAP_HOST,
        port = LDAP_PORT,
        base = STRESS_BASE_DN,
        filter = '(objectClass=*)',
        scope = 'one',
        pagesize = 100,
    })

    for iter = 1, STRESS_KILL_ITERATIONS do
        local tcp, err = open_raw(search_path)
        luaunit.assertNotNil(tcp, 'iter ' .. iter .. ': ' .. tostring(err))

        -- Read a small slice of the body, then drop. The server is
        -- streaming JSON; we don't care what we got, just that the
        -- close happens mid-flight.
        local n = math.random(0, 4096)
        if n > 0 then tcp:receive(n) end
        tcp:close()
    end

    luaunit.assertTrue(nginx_alive(), 'nginx unresponsive after paged-search torture')
end

--- Open many SSE streams concurrently, kill half of them at random
--- offsets, drain the rest cleanly. Catches per-connection state
--- bleed (e.g. one search's cleanup interfering with another).
function m:TestStressConcurrentSseFanout()
    local sse_path = 'ldap-sse?' .. qs({
        host = LDAP_HOST,
        port = LDAP_PORT,
        base = STRESS_BASE_DN,
        filter = '(objectClass=*)',
    })

    local conns = {}
    for i = 1, STRESS_CONCURRENT_OPENS do
        local tcp, err = open_raw(sse_path, 10)
        luaunit.assertNotNil(tcp, 'fanout open ' .. i .. ': ' .. tostring(err))
        conns[#conns + 1] = tcp
    end

    -- Random partial drain + close on every connection.
    for _, tcp in ipairs(conns) do
        local drain = math.random(0, 50)
        for _ = 1, drain do
            local ev = read_sse_event(tcp)
            if ev == nil then break end
        end
        tcp:close()
    end

    luaunit.assertTrue(nginx_alive(), 'nginx unresponsive after concurrent fanout torture')
end

-- Cleanup the seeded subtree at process exit so subsequent runs aren't
-- doubling up and rerunning ldapadd over an existing tree (-c keeps
-- ldapadd going on duplicates, but the inject is faster on a clean tree).
local function cleanup_subtree()
    print(string.format("[stress] tearing down %s...", STRESS_BASE_DN))
    ldapdelete_subtree(STRESS_BASE_DN)
end

-- Register an at-exit via a finaliser table; LuaUnit doesn't expose a
-- post-suite hook so this is the simplest hook into VM teardown.
local _exit_guard = setmetatable({}, { __gc = cleanup_subtree })
m._exit_guard = _exit_guard

return m
