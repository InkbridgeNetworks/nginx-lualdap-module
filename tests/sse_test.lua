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

os.exit(lu.LuaUnit.run())
