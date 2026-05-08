local luaunit = require('luaunit')


local m = {}

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

-- ou=users always exists in the Bitnami tree and has a real DIT entry.
local REAL_DN = 'ou=users,dc=example,dc=org'

function m:TestCompareMatch()
    local headers, json = self:sendRequest('GET',
        'ldap-compare?' .. qs({ dn = REAL_DN, attr = 'ou', val = 'users' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(json.result, true)
end

function m:TestCompareNoMatch()
    local headers, json = self:sendRequest('GET',
        'ldap-compare?' .. qs({ dn = REAL_DN, attr = 'ou', val = '__not_users__' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(json.result, false)
end

function m:TestBadDn()
    local headers, json = self:sendRequest('GET',
        'ldap-compare?' .. qs({ dn = 'cn=__ghost__,dc=example,dc=org', attr = 'cn', val = 'x' }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
end

function m:TestMissingParams()
    local headers, json = self:sendRequest('GET',
        'ldap-compare?' .. qs({ dn = REAL_DN }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

function m:TestUnknownAttribute()
    -- Comparing against an attribute that doesn't exist in the schema should fail.
    local headers, json = self:sendRequest('GET',
        'ldap-compare?' .. qs({ dn = REAL_DN, attr = 'unknownAttr99x', val = 'x' }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
end

return m
