local luaunit = require('luaunit')


local m = {}

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

local BASE  = 'dc=example,dc=org'
local BIND  = 'cn=manager,dc=example,dc=org'
local PASS  = 'password'

function m:TestBaseScope()
    -- dc=example,dc=org is the root entry; base scope should return exactly it.
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'base', filter = '(objectClass=*)' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertNotNil(json.entries)
    luaunit.assertEquals(#json.entries, 1)
    luaunit.assertStrContains(json.entries[1].dn, 'dc=example')
end

function m:TestSubtreeReturnsEntries()
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'sub', filter = '(objectClass=*)' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertNotNil(json.entries)
    luaunit.assertIsTrue(#json.entries > 0)
end

function m:TestFilterNoMatch()
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'sub', filter = '(cn=__nonexistent_ci_entry__)' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    -- An empty result has no entries with a 'dn' key
    if json.entries then
        luaunit.assertEquals(#json.entries, 0)
    end
end

function m:TestPagedSearch()
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'sub', filter = '(objectClass=*)', pagesize = 1 }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    -- With pagesize=1 and multiple entries, more_pages should be true
    luaunit.assertNotNil(json.more_pages)
    -- At least one entry returned
    luaunit.assertIsTrue(#json.entries >= 1)
end

function m:TestOneLevelScope()
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'one', filter = '(objectClass=*)' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertNotNil(json.entries)
end

function m:TestBadBase()
    -- An unknown base may return an LDAP error or empty results depending on server config;
    -- either way the response must be valid JSON with an ok field.
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = 'cn=__bad__,dc=invalid', scope = 'sub', filter = '(objectClass=*)' }))
    luaunit.assertNotNil(json.ok)
end

function m:TestSizelimit()
    -- With sizelimit=1, at most one entry should come back even for a broad filter.
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'sub', filter = '(objectClass=*)', sizelimit = 1 }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertNotNil(json.entries)
    luaunit.assertEquals(#json.entries, 1)
end

function m:TestAttrsOnly()
    -- With attrsonly=1, attribute values should be empty arrays (names only, no values).
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'sub', filter = '(objectClass=*)', attrsonly = 1 }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertNotNil(json.entries)
    luaunit.assertIsTrue(#json.entries > 0)
    -- lualdap represents attrsonly values as `true`; check all attr values are boolean true
    for _, entry in ipairs(json.entries) do
        for _, v in pairs(entry.attrs or {}) do
            luaunit.assertEquals(v, true)
        end
    end
end

function m:TestInvalidScope()
    -- Uppercase/invalid scope value should produce an error.
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = BASE, scope = 'INVALID', filter = '(objectClass=*)' }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
end

return m
