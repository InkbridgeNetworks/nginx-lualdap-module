local luaunit = require('luaunit')
local socket  = require('socket')

local m = {}

local NGINX_HOST = os.getenv('NGINX_HOST') or '127.0.0.1'
local NGINX_PORT = tonumber(os.getenv('NGINX_PORT') or os.getenv('TEST_PORT') or '8090')

local function url_encode(s)
    return (tostring(s):gsub('[^%w._~-]', function(c)
        return string.format('%%%02X', string.byte(c))
    end))
end

-- Most callers need raw values (LDAP filters with parens, DNs with =,
-- etc.). Only encode when the value would otherwise break parsing.
local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

-- Open a raw TCP connection using HTTP/1.0 so nginx streams SSE without
-- chunked transfer encoding (lua_http10_buffering off handles this).
-- Returns (tcp, response_headers_table).
local function open_sse(path_and_query)
    local tcp = socket.tcp()
    tcp:settimeout(5)
    local ok, err = tcp:connect(NGINX_HOST, NGINX_PORT)
    luaunit.assertNil(err, 'SSE connect: ' .. tostring(err))
    tcp:send('GET /' .. path_and_query .. ' HTTP/1.0\r\nHost: ' .. NGINX_HOST .. '\r\n\r\n')
    -- Collect HTTP response headers before the blank line.
    local headers = {}
    while true do
        local line = tcp:receive('*l')
        if not line or line:gsub('\r', '') == '' then break end
        local name, val = line:match('^([^:]+):%s*(.-)%s*$')
        if name then
            headers[name:lower()] = val
        end
    end
    return tcp, headers
end

-- Read one SSE event (event + data lines) from the raw TCP socket.
-- Returns event_type, data, id_val (id_val is nil if no id: line), or nil on EOF/timeout.
local function read_sse_event(tcp)
    local event_type, data_val, id_val
    while true do
        local line, err = tcp:receive('*l')
        if not line then return nil, nil, nil end
        line = line:gsub('\r', '')
        if line == '' then
            if event_type or data_val or id_val then
                return event_type or 'message', data_val or '', id_val
            end
        elseif line:sub(1, 7) == 'event: ' then
            event_type = line:sub(8)
        elseif line:sub(1, 6) == 'data: ' then
            data_val = line:sub(7)
        elseif line:sub(1, 4) == 'id: ' then
            id_val = line:sub(5)
        end
    end
end

-- Drain entries until the streamBegins marker arrives. Use this in
-- tests that perform a 'do op -> expect SSE event' check: without it
-- the op races against the syncrepl refresh phase and the per-entry
-- event may be folded into refreshDone's queue-drain instead of
-- arriving as a discrete entry.
local function wait_for_stream_begins(tcp)
    while true do
        local ev = read_sse_event(tcp)
        if ev == nil or ev == 'streamBegins' then return ev end
    end
end

function m:TestStreamBeginsEvent()
    -- Filter matches nothing so the refresh phase has zero entries and
    -- streamBegins is the first event we see.
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(cn=__no_match_for_ready__)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'streamBegins')
    luaunit.assertNotNil(data)
end

function m:TestStreamBeginsEventDataIsEmptyObject()
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(cn=__no_match_for_ready__)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'streamBegins')
    luaunit.assertEquals(data, '{}')
end

function m:TestEntryEventDuringRefresh()
    -- A filter that matches at least one existing entry yields an
    -- entry event during the refresh phase before streamBegins fires.
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(objectClass=*)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'entry')
    luaunit.assertStrContains(data, '"dn"')
end

function m:TestEntryDataContainsDn()
    -- ou=users always exists in the Bitnami tree.
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(ou=users)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'entry')
    luaunit.assertStrContains(data, 'ou=users')
end

function m:TestEntryDataContainsAttrs()
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(ou=users)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'entry')
    luaunit.assertStrContains(data, '"attrs"')
end

function m:TestErrorEventOnBadPort()
    local tcp = open_sse('ldap-sse?' .. qs({ port = 1 }))
    local ev = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'error')
end

function m:TestResponseHeadersContentType()
    local _, headers = open_sse('ldap-sse')
    luaunit.assertStrContains(headers['content-type'] or '', 'text/event-stream')
end

function m:TestResponseHeadersCacheControl()
    local _, headers = open_sse('ldap-sse')
    luaunit.assertStrContains(headers['cache-control'] or '', 'no-cache')
end

-- entryUUID is now a metadata field at the top level of the SSE record,
-- sourced from the Sync State Control on every persistent-search entry, so
-- it is always present regardless of the attrs request list.
function m:TestEntryUUIDAlwaysPresent()
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(ou=users)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'entry')
    luaunit.assertNotNil(string.match(data, '"entryUUID":"%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x"'))
end

function m:TestEntryUUIDNotInsideAttrs()
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(ou=users)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'entry')
    -- entryUUID is metadata; attrs holds real attributes only.
    -- When attrs is not requested, the server omits entryUUID from attrs.
    local attrs = data:match('"attrs":({.-})')
    luaunit.assertNotNil(attrs, 'no attrs object in payload: ' .. data)
    luaunit.assertNotStrContains(attrs, 'entryUUID')
end

-- The persistent search auto-appends entryUUID to whatever attrs the caller
-- requested, and strips it from the response attrs table. So even with an
-- explicit narrow attrs request, entryUUID lives only at the top level.
function m:TestEntryUUIDStrippedWhenCallerRequestsAttrs()
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(ou=users)', attrs = 'ou' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'entry')
    -- Top-level UUID is there
    luaunit.assertNotNil(string.match(data, '"entryUUID":"%x'))
    -- attrs has 'ou' (what the caller asked for) but NOT entryUUID
    local attrs = data:match('"attrs":({.-})')
    luaunit.assertNotNil(attrs, 'no attrs object: ' .. data)
    luaunit.assertStrContains(attrs, '"ou"')
    luaunit.assertNotStrContains(attrs, 'entryUUID')
end

function m:TestSyncStatePresentOnInitialSync()
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(ou=users)' }))
    local ev, data = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev, 'entry')
    -- Initial-sync entries arrive with op=add in refreshAndPersist mode
    luaunit.assertStrContains(data, '"syncOp":"add"')
end

function m:TestRenameEventCount()
    local SSE_SRC_DN  = 'cn=ci_sse_evcount_src,dc=example,dc=org'
    local SSE_DST_RDN = 'cn=ci_sse_evcount_dst'
    local SSE_DST_DN  = SSE_DST_RDN .. ',dc=example,dc=org'

    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = SSE_SRC_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SSE_SRC_DN }))
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SSE_DST_DN }))
    end)

    -- OR filter matches both names so we catch every notification the server
    -- emits during the rename (RFC 4533 modify-in-scope vs delete+add pair).
    local filter = '(|(cn=ci_sse_evcount_src)(cn=ci_sse_evcount_dst))'
    local tcp = open_sse('ldap-sse?' .. qs({ filter = filter }))

    -- Drain refresh-phase entry for the src name, then wait for the
    -- refresh->persist transition before issuing the rename; otherwise
    -- the change can race the refresh phase and the per-entry
    -- notification gets folded into the queue-drained refreshDone.
    local ev1 = read_sse_event(tcp)
    luaunit.assertEquals(ev1, 'entry')
    luaunit.assertEquals(wait_for_stream_begins(tcp), 'streamBegins')

    self:sendRequest('GET', 'ldap-rename?' .. qs({
        dn           = SSE_SRC_DN,
        newrdn       = SSE_DST_RDN,
        deleteoldrdn = 1,
    }))

    -- Short timeout: server pushes notifications synchronously so 1 s is ample.
    tcp:settimeout(1)
    local events = {}
    while true do
        local ev, data = read_sse_event(tcp)
        if not ev then break end
        events[#events + 1] = { ev = ev, data = data }
    end
    tcp:close()

    -- Hypothesis: one modify event with the new DN.  If OpenLDAP sends a
    -- delete+add pair instead, this fails and we update the assertion.
    luaunit.assertEquals(#events, 1)
    luaunit.assertStrContains(events[1].data, 'ci_sse_evcount_dst')

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SSE_DST_DN }))
end

function m:TestRenameAppearsAsEntryEvent()
    local SSE_SRC_DN  = 'cn=ci_sse_rename_src,dc=example,dc=org'
    local SSE_DST_RDN = 'cn=ci_sse_rename_dst'
    local SSE_DST_DN  = SSE_DST_RDN .. ',dc=example,dc=org'

    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = SSE_SRC_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SSE_SRC_DN }))
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SSE_DST_DN }))
    end)

    -- Filter on the destination name: initial sync returns zero matches,
    -- so streamBegins is the first event we see (refresh phase has no
    -- entries to emit). After the rename the entry enters scope and the
    -- server pushes it.
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(cn=ci_sse_rename_dst)' }))
    local ev1 = read_sse_event(tcp)
    luaunit.assertEquals(ev1, 'streamBegins')

    self:sendRequest('GET', 'ldap-rename?' .. qs({
        dn           = SSE_SRC_DN,
        newrdn       = SSE_DST_RDN,
        deleteoldrdn = 1,
    }))

    local ev2, data = read_sse_event(tcp)
    tcp:close()

    luaunit.assertEquals(ev2, 'entry')
    luaunit.assertStrContains(data, 'ci_sse_rename_dst')

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SSE_DST_DN }))
end

local UUID_PAT = '(%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x)'

-- Delete notifications carry no regular attributes, so set_attribs cannot
-- supply entryUUID. The only path that can is the Sync State Control extracted
-- by push_sync_state_uuid. This test isolates that path: capture the UUID from
-- the initial-sync entry, delete the object, then assert the same UUID appears
-- in the resulting notification.
function m:TestEntryUUIDOnDelete()
    local DN = 'cn=ci_sse_delete_uuid,dc=example,dc=org'

    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DN }))
    end)

    local tcp = open_sse('ldap-sse?' .. qs({
        filter = '(cn=ci_sse_delete_uuid)',
        attrs  = 'entryUUID',
    }))

    -- Initial sync delivers the entry with its UUID via set_attribs.
    -- Then wait for the refresh->persist transition; see TestRenameEventCount.
    local ev1, data1 = read_sse_event(tcp)
    luaunit.assertEquals(ev1, 'entry')
    local initial_uuid = data1:match('"entryUUID":"' .. UUID_PAT .. '"')
    luaunit.assertNotNil(initial_uuid, 'no UUID in initial-sync entry: ' .. data1)
    luaunit.assertEquals(wait_for_stream_begins(tcp), 'streamBegins')

    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DN }))

    tcp:settimeout(2)
    local ev3, data3, id3 = read_sse_event(tcp)
    tcp:close()

    luaunit.assertEquals(ev3, 'entry')
    luaunit.assertStrContains(data3, '"entryUUID":"' .. initial_uuid .. '"')
    luaunit.assertStrContains(data3, '"syncOp":"delete"')
    -- The refreshDelete intermediate fires between initial sync and the
    -- delete notification, so the cookie has been advanced and stamped.
    local body_cookie = data3:match('"syncCookie":"([^"]+)"')
    luaunit.assertNotNil(body_cookie, 'no syncCookie in delete event: ' .. data3)
    -- The same cookie must appear in the SSE id: line for resumption.
    luaunit.assertEquals(id3, body_cookie)
end

-- Resumption: capture a cookie from a delete event on a fresh sync, then
-- reconnect with that cookie. The server must accept the cookie and skip
-- the refresh phase, so on the second connection we should see new changes
-- without the entries that already existed at cookie time being replayed
-- as syncOp=add.
function m:TestPersistentSearchResumesFromCookie()
    local DN_A = 'cn=ci_resume_a,dc=example,dc=org'
    local DN_B = 'cn=ci_resume_b,dc=example,dc=org'
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DN_A }))
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DN_B }))
    end)

    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = DN_A }))

    -- First connection: full refresh delivers DN_A as an entry, then
    -- the streamBegins marker, then we delete the entry to force the
    -- server to advance the cookie.
    local tcp = open_sse('ldap-sse?' .. qs({ filter = '(cn=ci_resume_a)' }))
    local ev1 = read_sse_event(tcp)
    luaunit.assertEquals(ev1, 'entry')
    luaunit.assertEquals(wait_for_stream_begins(tcp), 'streamBegins')

    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DN_A }))

    tcp:settimeout(2)
    local ev2, data2, id2 = read_sse_event(tcp)
    tcp:close()
    luaunit.assertEquals(ev2, 'entry')
    luaunit.assertStrContains(data2, '"syncOp":"delete"')
    luaunit.assertNotNil(id2, 'no cookie captured from delete event')
    local cookie = id2

    -- Reconnect with the cookie. Filter widened so a freshly-added DN_B
    -- enters scope after the resume, exercising change detection.
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = DN_B }))

    -- Cookie has '=' and ',' so we percent-encode it; other params are
    -- LDAP filter syntax and stay raw.
    local tcp2 = open_sse('ldap-sse?'
        .. 'filter=(|(cn=ci_resume_a)(cn=ci_resume_b))'
        .. '&cookie=' .. url_encode(cookie))

    -- The server must replay DN_B (added after the cookie). DN_A was
    -- deleted before the cookie so it should NOT be replayed as add.
    tcp2:settimeout(3)
    local ev3, data3 = read_sse_event(tcp2)
    tcp2:close()

    luaunit.assertEquals(ev3, 'entry')
    luaunit.assertStrContains(data3, 'ci_resume_b')
    luaunit.assertNotStrContains(data3, 'ci_resume_a')
end

return m
