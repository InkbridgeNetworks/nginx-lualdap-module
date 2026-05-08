#!/usr/bin/env lua5.1
--
-- SSE endpoint tests for lualdap-nginx-module.
--
-- Requires:
--   luaunit  (luarocks install luaunit)
--   luasocket (luarocks install luasocket)
--
-- Environment variables (all optional, defaults match ldap-container.sh):
--   NGINX_HOST   default 127.0.0.1
--   NGINX_PORT   default 8080
--   LDAP_HOST    default 127.0.0.1
--   LDAP_PORT    default 389
--   LDAP_BASE    default dc=example,dc=org
--   LDAP_BIND    default cn=manager,dc=example,dc=org
--   LDAP_PASS    default password

local lu     = require("luaunit")
local socket = require("socket")
local http   = require("socket.http")
local ltn12  = require("ltn12")

local NGINX_HOST = os.getenv("NGINX_HOST") or "127.0.0.1"
local NGINX_PORT = tonumber(os.getenv("NGINX_PORT")) or 8080
local LDAP_HOST  = os.getenv("LDAP_HOST")  or "127.0.0.1"
local LDAP_PORT  = tonumber(os.getenv("LDAP_PORT"))  or 389
local LDAP_BASE  = os.getenv("LDAP_BASE")  or "dc=example,dc=org"
local LDAP_BIND  = os.getenv("LDAP_BIND")  or "cn=manager,dc=example,dc=org"
local LDAP_PASS  = os.getenv("LDAP_PASS")  or "password"

-- Strip --parallel / -p from arg before LuaUnit parses it.
local _parallel_mode = false
do
    local i = 1
    while i <= #arg do
        if arg[i] == "--parallel" or arg[i] == "-p" then
            _parallel_mode = true
            table.remove(arg, i)
        else
            i = i + 1
        end
    end
end

-- SSE endpoint URL (query params let the handler pick up LDAP config)
local SSE_PATH = string.format(
    "/ldap-sse?host=%s&port=%d&base=%s&bind=%s&pass=%s",
    LDAP_HOST, LDAP_PORT, LDAP_BASE, LDAP_BIND, LDAP_PASS
)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Open a raw TCP connection to nginx and send an HTTP/1.1 GET.
-- Returns the connected socket with headers consumed, or nil + error string.
local function sse_open(path, timeout_s)
    timeout_s = timeout_s or 10
    local tcp = socket.tcp()
    tcp:settimeout(timeout_s)

    local ok, err = tcp:connect(NGINX_HOST, NGINX_PORT)
    if not ok then
        return nil, "connect: " .. err
    end

    local req = table.concat({
        "GET " .. path .. " HTTP/1.1",
        "Host: " .. NGINX_HOST .. ":" .. NGINX_PORT,
        "Accept: text/event-stream",
        "Connection: keep-alive",
        "",
        "",
    }, "\r\n")
    tcp:send(req)

    -- Read and verify status line
    local status, err = tcp:receive("*l")
    if not status then
        tcp:close()
        return nil, "no status: " .. tostring(err)
    end
    if not status:match("^HTTP/1%.%d 200") then
        tcp:close()
        return nil, "unexpected status: " .. status
    end

    -- Collect response headers
    local headers = {}
    while true do
        local line, err = tcp:receive("*l")
        if not line or line == "" then break end
        local k, v = line:match("^([^:]+):%s*(.+)")
        if k then headers[k:lower()] = v end
    end

    return tcp, headers
end

-- Read one SSE event (event + data lines, terminated by blank line).
-- Returns event_type (string), data (string), or nil + reason on timeout/close.
local function sse_read_event(tcp)
    local event_type = "message"
    local data_parts = {}

    while true do
        local line, err = tcp:receive("*l")
        if not line then
            return nil, (err or "closed")
        end
        if line:match("^event:") then
            event_type = line:match("^event:%s*(.+)") or event_type
        elseif line:match("^data:") then
            data_parts[#data_parts + 1] = line:match("^data:%s*(.*)")
        elseif line == "" then
            if #data_parts > 0 then
                return event_type, table.concat(data_parts, "\n")
            end
            -- blank line with no data = keep-alive comment, continue
        end
    end
end

-- Drain all events arriving within `timeout_s` seconds.
-- Returns a table of {type, data} pairs.
local function sse_drain(tcp, timeout_s)
    timeout_s = timeout_s or 1
    local events = {}
    local saved = tcp:gettimeout()
    tcp:settimeout(timeout_s)
    while true do
        local etype, data = sse_read_event(tcp)
        if not etype then break end
        events[#events + 1] = { type = etype, data = data }
    end
    tcp:settimeout(saved)
    return events
end

local function ldap_modify_description(dn, value)
    local path = string.format(
        "/ldap-modify?host=%s&port=%d&bind=%s&pass=%s&dn=%s&attr=description&val=%s",
        LDAP_HOST, LDAP_PORT, LDAP_BIND, LDAP_PASS, dn, value
    )
    local body = {}
    local _, status = http.request({
        url     = string.format("http://%s:%d%s", NGINX_HOST, NGINX_PORT, path),
        sink    = ltn12.sink.table(body),
    })
    local ok = status == 200 and table.concat(body):find('"ok":true', 1, true)
    return ok ~= nil, table.concat(body)
end

-- Issue a request to /ldap-modify with explicit params.
-- Connection params (host/port/bind/pass) default to the env-var values.
-- Operation params (dn/attr/val) are omitted when not provided (triggering 400).
local function modify_request(params)
    local q = {}
    q[#q+1] = "host=" .. (params.host or LDAP_HOST)
    q[#q+1] = "port=" .. (params.port or LDAP_PORT)
    q[#q+1] = "bind=" .. (params.bind or LDAP_BIND)
    q[#q+1] = "pass=" .. (params.pass or LDAP_PASS)
    if params.dn   then q[#q+1] = "dn="   .. params.dn   end
    if params.attr then q[#q+1] = "attr=" .. params.attr end
    if params.val  then q[#q+1] = "val="  .. params.val  end
    local body = {}
    local _, status = http.request({
        url  = string.format("http://%s:%d/ldap-modify?%s",
                             NGINX_HOST, NGINX_PORT, table.concat(q, "&")),
        sink = ltn12.sink.table(body),
    })
    return status, table.concat(body)
end

-- Generic helper: GET an endpoint that returns JSON, return status + body string.
local function get_request(path)
    local body = {}
    local _, status = http.request({
        url  = string.format("http://%s:%d%s", NGINX_HOST, NGINX_PORT, path),
        sink = ltn12.sink.table(body),
    })
    return status, table.concat(body)
end

-- Build a query string from a params table.
local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = tostring(k) .. "=" .. tostring(v)
    end
    return table.concat(parts, "&")
end

-- Connection param defaults shared by all LDAP operation helpers.
local conn_defaults = {
    host = LDAP_HOST,
    port = LDAP_PORT,
    bind = LDAP_BIND,
    pass = LDAP_PASS,
}

local function add_request(params)
    local p = {}
    for k, v in pairs(conn_defaults) do p[k] = v end
    for k, v in pairs(params) do p[k] = v end
    return get_request("/ldap-add?" .. qs(p))
end

local function delete_request(params)
    local p = {}
    for k, v in pairs(conn_defaults) do p[k] = v end
    for k, v in pairs(params) do p[k] = v end
    return get_request("/ldap-delete?" .. qs(p))
end

local function compare_request(params)
    local p = {}
    for k, v in pairs(conn_defaults) do p[k] = v end
    for k, v in pairs(params) do p[k] = v end
    return get_request("/ldap-compare?" .. qs(p))
end

local function rename_request(params)
    local p = {}
    for k, v in pairs(conn_defaults) do p[k] = v end
    for k, v in pairs(params) do p[k] = v end
    return get_request("/ldap-rename?" .. qs(p))
end

local function search_request(params)
    local p = {}
    for k, v in pairs(conn_defaults) do p[k] = v end
    for k, v in pairs(params) do p[k] = v end
    return get_request("/ldap-search?" .. qs(p))
end

local function getfd_request(params)
    local p = { host = LDAP_HOST, port = LDAP_PORT }
    for k, v in pairs(params or {}) do p[k] = v end
    return get_request("/ldap-getfd?" .. qs(p))
end

-- Wait until nginx is accepting connections (up to `tries` half-second attempts).
local function wait_for_nginx(tries)
    tries = tries or 20
    for _ = 1, tries do
        local s = socket.tcp()
        s:settimeout(0.5)
        local ok = s:connect(NGINX_HOST, NGINX_PORT)
        s:close()
        if ok then return true end
        socket.sleep(0.5)
    end
    return false
end

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

TestSSE = {}

function TestSSE:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- Verify the endpoint sets SSE-required headers.
function TestSSE:test_01_headers()
    local tcp, headers = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp, tostring(headers))  -- headers holds error string on failure

    local ct = headers["content-type"] or ""
    lu.assertStrContains(ct, "text/event-stream", false,
        "Content-Type should be text/event-stream, got: " .. ct)

    tcp:close()
end

-- Verify the first event is always "ready".
function TestSSE:test_02_ready_event()
    local tcp, err = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp, err)

    tcp:settimeout(10)
    local etype, data = sse_read_event(tcp)
    lu.assertEquals(etype, "ready",
        "first event should be 'ready', got: " .. tostring(etype))

    tcp:close()
end

-- Verify initial LDAP entries arrive during the syncrepl refresh phase.
function TestSSE:test_03_initial_sync_entries()
    local tcp, err = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp, err)

    -- Skip the ready event
    tcp:settimeout(10)
    sse_read_event(tcp)

    -- Collect entries for up to 5 seconds; the bitnami bootstrap creates at
    -- least one user (uid=api), so we should see at least one entry event.
    local events = sse_drain(tcp, 5)
    tcp:close()

    local entry_count = 0
    for _, ev in ipairs(events) do
        if ev.type == "entry" then entry_count = entry_count + 1 end
    end
    lu.assertTrue(entry_count >= 1,
        "expected at least 1 entry event during initial sync, got " .. entry_count)
end

-- Verify a live LDAP change triggers an entry event in the persist phase.
function TestSSE:test_04_live_change_event()
    local tcp, err = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp, err)
    tcp:settimeout(10)

    -- Consume ready + initial sync entries
    sse_read_event(tcp)          -- ready
    sse_drain(tcp, 5)            -- initial sync burst

    -- Inject a modify
    local target_dn = "cn=api,ou=users," .. LDAP_BASE
    local marker    = "sse-test-" .. os.time()
    local ok, out = ldap_modify_description(target_dn, marker)
    lu.assertTrue(ok, "ldapmodify failed: " .. out)

    -- Expect at least one entry event within 10 seconds
    tcp:settimeout(10)
    local found = false
    for _ = 1, 5 do
        local etype, data = sse_read_event(tcp)
        if not etype then break end
        if etype == "entry" then
            found = true
            lu.assertStrContains(data, '"dn"',    false, "entry event missing 'dn' field")
            lu.assertStrContains(data, '"attrs"', false, "entry event missing 'attrs' field")
            break
        end
    end
    tcp:close()

    lu.assertTrue(found, "no entry event received after LDAP modify")
end

-- Verify nginx survives an abrupt client disconnect mid-stream.
function TestSSE:test_05_abrupt_disconnect()
    local tcp, err = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp, err)

    tcp:settimeout(5)
    sse_read_event(tcp)   -- consume ready so we're definitely past the bind

    -- Abrupt close with no LDAP unbind from our side
    tcp:close()
    socket.sleep(0.3)

    -- nginx should still be alive and serving requests
    local body = {}
    local _, code = http.request({
        url     = string.format("http://%s:%d/nginx_status", NGINX_HOST, NGINX_PORT),
        sink    = ltn12.sink.table(body),
    })
    -- /nginx_status denies all except 127.0.0.1; 403 is fine, 502/0 means nginx died
    lu.assertTrue(code == 200 or code == 403,
        "nginx not responding after SSE disconnect, got HTTP " .. tostring(code))
end

-- Verify two concurrent SSE connections both receive initial entries.
function TestSSE:test_06_concurrent_connections()
    local tcp1, err1 = sse_open(SSE_PATH, 5)
    local tcp2, err2 = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp1, err1)
    lu.assertNotNil(tcp2, err2)

    tcp1:settimeout(10)
    tcp2:settimeout(10)

    local e1 = sse_read_event(tcp1)
    local e2 = sse_read_event(tcp2)

    lu.assertEquals(e1, "ready", "conn1: first event should be ready")
    lu.assertEquals(e2, "ready", "conn2: first event should be ready")

    tcp1:close()
    tcp2:close()
end

-- Verify Cache-Control and X-Accel-Buffering are set correctly for SSE.
function TestSSE:test_07_sse_headers_cache_control()
    local tcp, headers = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp, tostring(headers))

    lu.assertEquals(headers["cache-control"], "no-cache",
        "Cache-Control should be no-cache, got: " .. tostring(headers["cache-control"]))

    tcp:close()
end

-- Verify the ready event carries an empty JSON object as its data payload.
function TestSSE:test_08_ready_event_data_format()
    local tcp, err = sse_open(SSE_PATH, 5)
    lu.assertNotNil(tcp, err)

    tcp:settimeout(10)
    local etype, data = sse_read_event(tcp)
    lu.assertEquals(etype, "ready")
    lu.assertEquals(data, "{}", "ready event data should be {}, got: " .. tostring(data))

    tcp:close()
end

-- Verify the endpoint emits an "error" SSE event when the LDAP port is unreachable.
-- Port 1 on the LDAP host is almost certainly closed; ECONNREFUSED is immediate.
function TestSSE:test_09_error_event_on_bad_ldap_port()
    local bad_path = string.format(
        "/ldap-sse?host=%s&port=1&base=%s&bind=%s&pass=%s",
        LDAP_HOST, LDAP_BASE, LDAP_BIND, LDAP_PASS
    )
    local tcp, err = sse_open(bad_path, 10)
    lu.assertNotNil(tcp, tostring(err))

    tcp:settimeout(10)
    local etype, data = sse_read_event(tcp)
    lu.assertEquals(etype, "error",
        "expected 'error' event on bad LDAP port, got: " .. tostring(etype))
    lu.assertStrContains(data, '"msg"', false, "error event data missing 'msg' field")

    tcp:close()
end

-- ---------------------------------------------------------------------------
-- /ldap-modify endpoint tests
-- ---------------------------------------------------------------------------

TestModify = {}

function TestModify:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- A well-formed request returns HTTP 200 with {"ok":true}.
function TestModify:test_01_success()
    local status, body = modify_request({
        dn   = "cn=api,ou=users," .. LDAP_BASE,
        attr = "description",
        val  = "modify-test-" .. os.time(),
    })
    lu.assertEquals(status, 200, "expected 200, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":true', false, "response missing ok:true")
end

-- Omitting dn must return 400.
function TestModify:test_02_missing_dn()
    local status, body = modify_request({ attr = "description", val = "x" })
    lu.assertEquals(status, 400, "expected 400 for missing dn, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
end

-- Omitting attr must return 400.
function TestModify:test_03_missing_attr()
    local status, body = modify_request({
        dn  = "cn=api,ou=users," .. LDAP_BASE,
        val = "x",
    })
    lu.assertEquals(status, 400, "expected 400 for missing attr, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
end

-- Omitting val must return 400.
function TestModify:test_04_missing_val()
    local status, body = modify_request({
        dn   = "cn=api,ou=users," .. LDAP_BASE,
        attr = "description",
    })
    lu.assertEquals(status, 400, "expected 400 for missing val, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
end

-- Modifying a DN that does not exist must return 500 with an LDAP error.
function TestModify:test_05_nonexistent_dn()
    local status, body = modify_request({
        dn   = "cn=doesnotexist,ou=users," .. LDAP_BASE,
        attr = "description",
        val  = "x",
    })
    lu.assertEquals(status, 500, "expected 500 for nonexistent DN, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
    -- LDAP should report the error code (no such object = 32)
    lu.assertStrContains(body, '"code"', false, "500 response missing 'code' field")
end

-- ---------------------------------------------------------------------------
-- lualdap.get_fd tests
-- ---------------------------------------------------------------------------

TestGetFd = {}

function TestGetFd:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- get_fd must return a positive file descriptor number for a live connection.
function TestGetFd:test_01_returns_valid_fd()
    local status, body = getfd_request()
    lu.assertEquals(status, 200, "expected 200, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":true', false)
    lu.assertStrContains(body, '"fd"', false)
end

-- ---------------------------------------------------------------------------
-- conn:add tests
-- ---------------------------------------------------------------------------

TestAdd = {}

function TestAdd:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- Add a fresh entry and clean it up afterwards.
function TestAdd:test_01_success()
    local dn = "cn=lualdap-add-" .. os.time() .. ",ou=users," .. LDAP_BASE
    local status, body = add_request({ dn = dn })
    lu.assertEquals(status, 200, "add failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
    delete_request({ dn = dn })  -- cleanup; ignore result
end

-- Omitting dn returns 400.
function TestAdd:test_02_missing_dn()
    local status, body = add_request({})
    lu.assertEquals(status, 400, "expected 400 for missing dn, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
end

-- Adding the same DN twice returns 500 with an LDAP already-exists error (68).
function TestAdd:test_03_duplicate_dn()
    local dn = "cn=lualdap-dup-" .. os.time() .. ",ou=users," .. LDAP_BASE
    add_request({ dn = dn })                         -- first add
    local status, body = add_request({ dn = dn })    -- duplicate
    lu.assertEquals(status, 500, "expected 500 for duplicate DN, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
    lu.assertStrContains(body, '"code"', false, "500 response missing 'code' field")
    delete_request({ dn = dn })  -- cleanup
end

-- ---------------------------------------------------------------------------
-- conn:compare tests
-- ---------------------------------------------------------------------------

TestCompare = {}

function TestCompare:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- Compare with a known-matching value returns {"ok":true,"result":true}.
function TestCompare:test_01_match()
    local status, body = compare_request({
        dn   = "cn=api,ou=users," .. LDAP_BASE,
        attr = "cn",
        val  = "api",
    })
    lu.assertEquals(status, 200, "compare failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
    lu.assertStrContains(body, '"result":true', false, "expected result:true for matching value")
end

-- Compare with a non-matching value returns {"ok":true,"result":false}.
function TestCompare:test_02_no_match()
    local status, body = compare_request({
        dn   = "cn=api,ou=users," .. LDAP_BASE,
        attr = "cn",
        val  = "definitely-not-api",
    })
    lu.assertEquals(status, 200, "compare failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
    lu.assertStrContains(body, '"result":false', false, "expected result:false for non-matching value")
end

-- Compare against a non-existent DN returns 500.
function TestCompare:test_03_nonexistent_dn()
    local status, body = compare_request({
        dn   = "cn=doesnotexist,ou=users," .. LDAP_BASE,
        attr = "cn",
        val  = "doesnotexist",
    })
    lu.assertEquals(status, 500, "expected 500 for nonexistent DN, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
end

-- Omitting a required param returns 400.
function TestCompare:test_04_missing_params()
    local status, body = compare_request({
        dn   = "cn=api,ou=users," .. LDAP_BASE,
        attr = "cn",
        -- val omitted
    })
    lu.assertEquals(status, 400, "expected 400 for missing val, got " .. tostring(status))
end

-- ---------------------------------------------------------------------------
-- conn:delete tests
-- ---------------------------------------------------------------------------

TestDelete = {}

function TestDelete:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- Create an entry then delete it successfully.
function TestDelete:test_01_success()
    local dn = "cn=lualdap-del-" .. os.time() .. ",ou=users," .. LDAP_BASE
    local add_status, add_body = add_request({ dn = dn })
    lu.assertEquals(add_status, 200, "setup add failed: " .. tostring(add_body))

    local status, body = delete_request({ dn = dn })
    lu.assertEquals(status, 200, "delete failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
end

-- Deleting a non-existent DN returns 500 with an LDAP error code.
function TestDelete:test_02_nonexistent_dn()
    local status, body = delete_request({
        dn = "cn=doesnotexist,ou=users," .. LDAP_BASE,
    })
    lu.assertEquals(status, 500, "expected 500 for nonexistent DN, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
    lu.assertStrContains(body, '"code"', false)
end

-- Omitting dn returns 400.
function TestDelete:test_03_missing_dn()
    local status, body = delete_request({})
    lu.assertEquals(status, 400, "expected 400 for missing dn, got " .. tostring(status))
end

-- ---------------------------------------------------------------------------
-- conn:rename tests
-- ---------------------------------------------------------------------------

TestRename = {}

function TestRename:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- Create an entry, rename its RDN, verify success, clean up.
function TestRename:test_01_success()
    local t      = os.time()
    local old_dn = "cn=lualdap-rename-src-" .. t .. ",ou=users," .. LDAP_BASE
    local newrdn = "cn=lualdap-rename-dst-" .. t
    local new_dn = newrdn .. ",ou=users," .. LDAP_BASE

    add_request({ dn = old_dn })

    local status, body = rename_request({ dn = old_dn, newrdn = newrdn })
    lu.assertEquals(status, 200, "rename failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)

    delete_request({ dn = new_dn })  -- cleanup
end

-- Renaming a non-existent entry returns 500.
function TestRename:test_02_nonexistent_dn()
    local status, body = rename_request({
        dn     = "cn=doesnotexist,ou=users," .. LDAP_BASE,
        newrdn = "cn=whatever",
    })
    lu.assertEquals(status, 500, "expected 500 for nonexistent DN, got " .. tostring(status))
    lu.assertStrContains(body, '"ok":false', false)
end

-- Omitting newrdn returns 400.
function TestRename:test_03_missing_newrdn()
    local status, body = rename_request({
        dn = "cn=api,ou=users," .. LDAP_BASE,
    })
    lu.assertEquals(status, 400, "expected 400 for missing newrdn, got " .. tostring(status))
end

-- ---------------------------------------------------------------------------
-- conn:search + search:more_pages tests
-- ---------------------------------------------------------------------------

TestSearch = {}

function TestSearch:setUp()
    lu.assertTrue(wait_for_nginx(), "nginx not reachable at " .. NGINX_HOST .. ":" .. NGINX_PORT)
end

-- A base-scope search on a known DN returns exactly that one entry.
function TestSearch:test_01_base_scope()
    local status, body = search_request({
        base   = "cn=api,ou=users," .. LDAP_BASE,
        scope  = "base",
        filter = "(objectClass=*)",
    })
    lu.assertEquals(status, 200, "search failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
    lu.assertStrContains(body, '"entries"', false)
    lu.assertStrContains(body, '"dn"', false)
end

-- A subtree search returns at least one entry.
function TestSearch:test_02_subtree_returns_entries()
    local status, body = search_request({
        base   = LDAP_BASE,
        scope  = "sub",
        filter = "(objectClass=inetOrgPerson)",
    })
    lu.assertEquals(status, 200, "search failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
    -- At least the cn=api user must appear.
    lu.assertStrContains(body, '"dn"', false, "no dn fields in search results")
end

-- A filter that matches nothing returns no entry data.
function TestSearch:test_03_empty_result()
    local status, body = search_request({
        base   = LDAP_BASE,
        scope  = "sub",
        filter = "(cn=lualdap-guaranteed-no-match-xyzzy)",
    })
    lu.assertEquals(status, 200, "search failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
    -- No entries means no "dn" fields in the response body.
    lu.assertNil(body:find('"dn"', 1, true),
        "expected no results for impossible filter but got entries: " .. body)
end

-- Paged search with pagesize=1: more_pages is true when more entries exist,
-- false on the final page.
function TestSearch:test_04_paged_more_pages()
    -- Add two extra entries so we have at least two pages at pagesize=1.
    local t   = os.time()
    local dn1 = "cn=lualdap-page-a-" .. t .. ",ou=users," .. LDAP_BASE
    local dn2 = "cn=lualdap-page-b-" .. t .. ",ou=users," .. LDAP_BASE
    add_request({ dn = dn1 })
    add_request({ dn = dn2 })

    -- First page: pagesize=1 must yield more_pages=true.
    local status, body = search_request({
        base     = "ou=users," .. LDAP_BASE,
        scope    = "one",
        filter   = "(objectClass=inetOrgPerson)",
        pagesize = 1,
    })
    lu.assertEquals(status, 200, "first page search failed: " .. body)
    lu.assertStrContains(body, '"ok":true', false)
    lu.assertStrContains(body, '"more_pages":true', false,
        "expected more_pages:true for pagesize=1 with multiple entries")

    delete_request({ dn = dn1 })
    delete_request({ dn = dn2 })
end

-- ---------------------------------------------------------------------------
-- Parallel runner
-- ---------------------------------------------------------------------------

-- Discovers all Test* tables registered in the global env.
local function discover_classes()
    local names = {}
    for k, v in pairs(_G) do
        if type(v) == "table" and k:match("^Test") then
            names[#names+1] = k
        end
    end
    table.sort(names)
    return names
end

-- Run each test class as a subprocess, printing outputs as they complete,
-- then exit with 0 only if every class passed.
local function run_parallel()
    local lua_exe = (arg and arg[-1]) or "lua5.1"
    local script  = arg[0]
    local classes = discover_classes()

    local jobs = {}
    for _, cls in ipairs(classes) do
        local outfile  = os.tmpname()
        local donefile = os.tmpname()
        -- Shell: run class, capture all output, write exit code to sentinel.
        local cmd = string.format(
            "%s '%s' '%s' > '%s' 2>&1; echo $? > '%s' &",
            lua_exe, script, cls, outfile, donefile
        )
        os.execute(cmd)
        jobs[#jobs+1] = { cls = cls, outfile = outfile, donefile = donefile }
    end

    io.write(string.format("Running %d test class(es) in parallel...\n\n", #jobs))
    io.flush()

    -- Poll for completion (100 ms tick, 120 s ceiling).
    local deadline = socket.gettime() + 120
    while socket.gettime() < deadline do
        local pending = 0
        for _, job in ipairs(jobs) do
            if not job.rc then
                local f = io.open(job.donefile, "r")
                if f then
                    job.rc = tonumber(f:read("*l")) or 1
                    f:close()
                end
            end
            if not job.rc then pending = pending + 1 end
        end
        if pending == 0 then break end
        socket.sleep(0.1)
    end

    local overall = 0
    for _, job in ipairs(jobs) do
        local status_tag = (job.rc == 0) and "PASS" or "FAIL"
        local sep = string.rep("-", 60)
        io.write(string.format("\n%s\n[%s] %s\n%s\n", sep, status_tag, job.cls, sep))
        local f = io.open(job.outfile, "r")
        if f then
            io.write(f:read("*a"))
            f:close()
        end
        os.remove(job.outfile)
        os.remove(job.donefile)
        if (job.rc or 1) ~= 0 then overall = 1 end
    end

    os.exit(overall)
end

-- ---------------------------------------------------------------------------
-- Entry point
-- ---------------------------------------------------------------------------

if _parallel_mode then
    run_parallel()
else
    os.exit(lu.LuaUnit.run())
end
